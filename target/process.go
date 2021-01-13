package target

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

var (
	DebuggedProcess *TargetProcess
)

// TargetProcess 被调试进程信息
type TargetProcess struct {
	Process     *os.Process             // 进程信息
	Command     string                  // 进程启动命令，方便重启调试
	Args        []string                // 进程启动参数，方便重启调试
	Threads     map[int]*Thread         // 包含的线程列表,k=tid,v=thread
	Breakpoints map[uintptr]*Breakpoint // 已经添加的断点
	Kind        Kind                    // 发起调试的类型

	once       *sync.Once
	ptraceCh   chan func() // ptrace请求统一发送到这里，由专门协程处理
	ptraceDone chan int    // ptrace请求完成
	stopCh     chan int    // 通知需要停止调试
}
type Kind int

const (
	DEBUG Kind = iota
	EXEC
	ATTACH
)

// NewTargetProcess 创建一个待调试进程
func NewTargetProcess(cmd string, args ...string) (*TargetProcess, error) {
	var (
		target TargetProcess
		err    error
	)
	target = TargetProcess{
		Process:     nil,
		Command:     cmd,
		Args:        args,
		Threads:     map[int]*Thread{},
		Breakpoints: map[uintptr]*Breakpoint{},

		once:       &sync.Once{},
		ptraceCh:   make(chan func()),
		ptraceDone: make(chan int),
		stopCh:     make(chan int),
	}

	target.ExecPtrace(func() {
		// start and trace
		target.Process, err = target.launchCommand(cmd, args...)
		if err != nil {
			return
		}

		// trace newly created thread
		err = syscall.PtraceSetOptions(target.Process.Pid, syscall.PTRACE_O_TRACECLONE)
	})

	if err != nil {
		target.StopPtrace()
		return nil, err
	}

	return &target, nil
}

// AttachTargetProcess trace一个目标进程（准确地说是线程）
func AttachTargetProcess(pid int) (*TargetProcess, error) {
	var (
		target TargetProcess
		err    error
	)
	target = TargetProcess{
		Process:     nil,
		Command:     "",
		Args:        nil,
		Threads:     map[int]*Thread{},
		Breakpoints: map[uintptr]*Breakpoint{},
	}

	target.ExecPtrace(func() {
		// Attach to running process (thread)
		if err = target.Attach(pid); err != nil {
			return
		}

		if target.Process, err = os.FindProcess(pid); err != nil {
			return
		}

		// initialize the command and arguments,
		// after then, we could support restart command.
		if target.Command, err = readProcComm(pid); err != nil {
			return
		}

		if target.Args, err = readProcCommArgs(pid); err != nil {
			return
		}

		// Attach to other threads, and prepare to trace newly created thread
		if err = target.updateThreadList(); err != nil {
			return
		}
	})

	if err != nil {
		target.StopPtrace()
		return nil, err
	}

	return &target, nil
}

// launchCommand execute `execName` with `args`
//
// 为了方便调试，除了跟踪主线程，还需要考虑跟踪后续新创建的线程，linux 2.5.46中引入了以下ptrace选项，
// 通过设置该选项可以使得tracer自动跟踪新创建线程。
//
// PTRACE_O_TRACECLONE (since Linux 2.5.46)
//                     Stop the tracee at the next clone(2) and
//                     automatically start tracing the newly cloned
//                     process, which will start with a SIGSTOP, or
//                     PTRACE_EVENT_STOP if PTRACE_SEIZE was used.  A
//                     waitpid(2) by the tracer will return a status value.
//
// see more info by `man 2 ptrace`.
func (t *TargetProcess) launchCommand(execName string, args ...string) (*os.Process, error) {

	progCmd := exec.Command(execName, args...)
	progCmd.Stdin = os.Stdin
	progCmd.Stdout = os.Stdout
	progCmd.Stderr = os.Stderr

	progCmd.SysProcAttr = &syscall.SysProcAttr{
		Ptrace:     true, // implies PTRACE_TRACEME
		Setpgid:    true,
		Foreground: false,
	}
	progCmd.Env = os.Environ()

	// start the process
	err := progCmd.Start()
	if err != nil {
		return nil, err
	}

	// wait target process stopped
	var (
		status syscall.WaitStatus
		rusage syscall.Rusage
	)
	_, err = syscall.Wait4(progCmd.Process.Pid, &status, syscall.WALL, &rusage)
	if err != nil {
		return nil, err
	}
	fmt.Printf("process %d stopped: %v\n", progCmd.Process.Pid, status.Stopped())

	return progCmd.Process, nil
}

func (t *TargetProcess) ExecPtrace(fn func()) {
	t.once.Do(func() {
		go func() {
			// ensure all ptrace requests goes via the same tracer (thread)
			//
			// issue: https://github.com/golang/go/issues/7699
			//
			// 为什么syscall.PtraceDetach, detach error: no such process?
			// 因为ptrace请求应该来自相同的tracer线程，
			//
			// ps: 如果恰好不是，可能需要对tracee的状态显示进行更复杂的处理，需要考虑信号？目前看系统调用传递的参数是这样
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()

			for {
				select {
				case reqFn := <-t.ptraceCh:
					reqFn()
					t.ptraceDone <- 1
				case <-t.stopCh:
					break
				}
			}
		}()
	})
	t.ptraceCh <- fn
	<-t.ptraceDone
}

func (t *TargetProcess) StopPtrace() {
	close(t.stopCh)
}

// Attach Attach to process pid
func (t *TargetProcess) Attach(pid int) error {

	// check traceePID
	if !checkPid(pid) {
		return fmt.Errorf("process %d not existed\n", pid)
	}

	// Attach
	err := syscall.PtraceAttach(pid)
	if err != nil {
		return fmt.Errorf("process %d attached error: %v\n", pid, err)
	}
	fmt.Printf("process %d attached succ\n", pid)

	// wait
	var (
		status syscall.WaitStatus
		rusage syscall.Rusage
	)
	_, err = syscall.Wait4(pid, &status, syscall.WSTOPPED, &rusage)
	if err != nil {
		return fmt.Errorf("process %d waited error: %v\n", pid, err)
	}
	fmt.Printf("process %d stopped: %v\n", pid, status.Stopped())
	return nil
}

func (t *TargetProcess) Detach() error {

	// check traceePID
	if !checkPid(t.Process.Pid) {
		return fmt.Errorf("process %d not existed\n", t.Process.Pid)
	}

	// Detach all threads
	tids, err := t.loadThreadList()
	if err != nil {
		return err
	}

	for _, tid := range tids {
		t.ExecPtrace(func() {
			err = syscall.PtraceDetach(tid)
		})
		if err != nil {
			fmt.Printf("thread %d detached error: %v\n", tid, err)
			continue
		}
		fmt.Printf("thread %d detached succ\n", tid)

		//var status syscall.WaitStatus
		//_, err = syscall.Wait4(tid, &status, 0, nil)
		//if err != nil {
		//	return err
		//}
		//fmt.Printf("thread %d detached, status: %v\n", status)
	}
	return nil
}

func (t *TargetProcess) loadThreadList() ([]int, error) {
	threadIDs := []int{}

	tids, _ := filepath.Glob(fmt.Sprintf("/proc/%d/task/*", t.Process.Pid))
	for _, tidpath := range tids {
		tidstr := filepath.Base(tidpath)
		tid, err := strconv.Atoi(tidstr)
		if err != nil {
			return nil, err
		}
		threadIDs = append(threadIDs, tid)
	}
	return threadIDs, nil
}

func (t *TargetProcess) updateThreadList() error {

	tids, err := t.loadThreadList()
	if err != nil {
		return err
	}

	for _, tid := range tids {
		// Attach to thread
		err = syscall.PtraceAttach(tid)
		if err != nil && err != unix.EPERM {
			// Maybe we have traced tid via PTRACE_O_TRACECLONE.
			// If we try to Attach to it again, it will fail.
			// We should ignore this kind of error.
			return err
		}

		// wait thread
		var status unix.WaitStatus
		wpid, err := unix.Wait4(tid, &status, unix.WALL, nil)
		if err != nil {
			return err
		}
		if status.Exited() {
			fmt.Printf("thread already exited: %d\n", wpid)
		}

		// update thread
		err = syscall.PtraceSetOptions(tid, syscall.PTRACE_O_TRACECLONE)
		if err != nil {
			return err
		}

		t.Threads[tid] = &Thread{
			Tid:     tid,
			Status:  status,
			Process: t,
		}
	}
	return nil
}

// -------------------------------------------------------------------

// ProcessStart 启动被调试进程
func (t *TargetProcess) ProcessStart() error {
	return nil
}

// checkPid check whether traceePID is valid process's id
//
// On Unix systems, os.FindProcess always succeeds and returns a Process for
// the given traceePID, regardless of whether the process exists.
func checkPid(pid int) bool {
	out, err := exec.Command("kill", "-s", "0", strconv.Itoa(pid)).CombinedOutput()
	if err != nil {
		return false
	}

	// output error message, means traceePID is invalid
	if string(out) != "" {
		return false
	}

	return true
}

// --------------------------------------------------------------------

// ListBreakpoints 列出所有断点
func (t *TargetProcess) ListBreakpoints() {
	for _, b := range t.Breakpoints {
		fmt.Printf("breakpoint[%d] addr:%#x, loc:%s\n", b.ID, b.Addr, b.Pos)
	}
}

// AddBreakpoint 在地址addr处添加断点，返回新创建的断点
func (t *TargetProcess) AddBreakpoint(addr uintptr) (*Breakpoint, error) {
	var (
		breakpoint *Breakpoint
		err        error
	)

	t.ExecPtrace(func() {
		pid := DebuggedProcess.Process.Pid

		orig := [1]byte{}
		n, err := syscall.PtracePeekText(pid, addr, orig[:])
		if err != nil || n != 1 {
			err = fmt.Errorf("peek text, %d bytes, error: %v", n, err)
			return
		}

		breakpoint = newBreakPoint(addr, orig[0], "")
		DebuggedProcess.Breakpoints[addr] = breakpoint

		n, err = syscall.PtracePokeText(pid, addr, []byte{0xCC})
		if err != nil || n != 1 {
			err = fmt.Errorf("poke text, %d bytes, error: %v", n, err)
			return
		}
	})

	if err != nil {
		return nil, err
	}
	return breakpoint, nil
}

// ClearBreakpoint 删除addr处的断点
func (t *TargetProcess) ClearBreakpoint(addr uintptr) (*Breakpoint, error) {

	brk, ok := t.Breakpoints[addr]
	if !ok {
		return nil, errors.New("断点不存在")
	}

	// 移除断点
	pid := DebuggedProcess.Process.Pid

	var err error
	t.ExecPtrace(func() {
		var n int
		n, err = syscall.PtracePokeData(pid, brk.Addr, []byte{brk.Orig})
		if err != nil || n != 1 {
			err = fmt.Errorf("移除断点失败: %v", err)
			return
		}
		delete(t.Breakpoints, brk.Addr)
	})

	return brk, nil
}

// ClearAll 删除所有已添加的断点
func (t *TargetProcess) ClearAll() error {
	return nil
}

// Continue 执行到下一个断点处
func (t *TargetProcess) Continue() error {
	var err error
	t.ExecPtrace(func() {
		err = syscall.PtraceCont(t.Process.Pid, 0)
	})
	return err
}

// SingleStep 执行一条指令
func (t *TargetProcess) SingleStep() error {
	var err error
	t.ExecPtrace(func() {
		err = syscall.PtraceSingleStep(t.Process.Pid)
	})
	return err
}

// --------------------------------------------------------------------

// Disassemble 反汇编地址addr处的指令
func (t *TargetProcess) Disassemble(addr uintptr) ([]byte, error) {
	return nil, nil
}

// --------------------------------------------------------------------

// ReadMemory 读取内存地址addr处的数据，并存储到buf中，函数返回实际读取的字节数
func (t *TargetProcess) ReadMemory(addr uintptr, buf []byte) (int, error) {
	var (
		n   int
		err error
	)
	t.ExecPtrace(func() {
		// PtracePeekText 与 PtracePeekData 效果相同
		n, err = syscall.PtracePeekText(t.Process.Pid, addr, buf)
	})
	return n, err
}

// SetVariable 设置内存地址addr处的值为value
func (t *TargetProcess) WriteMemory(addr uintptr, value []byte) error {
	return nil
}

// ReadRegister 读取寄存器的数据
func (t *TargetProcess) ReadRegister() (*syscall.PtraceRegs, error) {
	var (
		regs syscall.PtraceRegs
		err  error
	)

	t.ExecPtrace(func() {
		pid := DebuggedProcess.Process.Pid
		err = syscall.PtraceGetRegs(pid, &regs)
		if err != nil {
			err = fmt.Errorf("get regs error: %v", err)
		}
	})

	if err != nil {
		return nil, err
	}
	return &regs, nil
}

// WriteRegister 设置寄存器reg的值为value
func (t *TargetProcess) WriteRegister(regs *syscall.PtraceRegs) error {
	var err error
	t.ExecPtrace(func() {
		pid := DebuggedProcess.Process.Pid
		err = syscall.PtraceSetRegs(pid, regs)
	})
	return err
}

// --------------------------------------------------------------------

// Backtrace 获取调用栈信息
func (t *TargetProcess) Backtrace() ([]byte, error) {
	return nil, nil
}

// Frame 返回${idx}th个栈帧的信息
func (t *TargetProcess) Frame(idx int) error {
	return nil
}
