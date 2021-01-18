package target

import (
	"bufio"
	"debug/elf"
	"debug/gosym"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/hitzhangjie/godbg/pkg/symbol"
	"golang.org/x/arch/x86/x86asm"
	"golang.org/x/sys/unix"
)

var DBPProcess *DebuggedProcess

// DebuggedProcess 被调试进程信息
type DebuggedProcess struct {
	Process *os.Process     // 进程信息
	Threads map[int]*Thread // 包含的线程列表,k=tid,v=thread

	Command string   // 进程启动命令，方便重启调试
	Args    []string // 进程启动参数，方便重启调试
	Kind    Kind     // 发起调试的类型

	BInfo       *symbol.BinaryInfo      // 符号层操作
	Table       *gosym.Table            // 用来在pc和file lineno、func之间做转换
	Breakpoints map[uintptr]*Breakpoint // 已经添加的断点

	once       *sync.Once
	ptraceCh   chan func() // ptrace请求统一发送到这里，由专门协程处理
	ptraceDone chan int    // ptrace请求完成
	stopCh     chan int    // 通知需要停止调试
}

// NewDebuggedProcess 创建一个待调试进程
func NewDebuggedProcess(cmd string, args []string, kind Kind) (*DebuggedProcess, error) {
	var (
		target DebuggedProcess
		err    error
	)
	target = DebuggedProcess{
		Process:     nil,
		Threads:     map[int]*Thread{},
		Command:     cmd,
		Args:        args,
		Kind:        kind,
		Breakpoints: map[uintptr]*Breakpoint{},
		once:        &sync.Once{},
		ptraceCh:    make(chan func()),
		ptraceDone:  make(chan int),
		stopCh:      make(chan int),
	}
	defer func() {
		if err != nil {
			target.StopPtrace()
		}
	}()

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
		return nil, err
	}

	// load line table
	err = target.loadLineTable()
	if err != nil {
		return nil, err
	}

	// load binary ifo
	bi, err := symbol.Analyze(cmd)
	if err != nil {
		return nil, err
	}
	target.BInfo = bi

	return &target, nil
}

// AttachTargetProcess trace一个目标进程（准确地说是线程）
func AttachTargetProcess(pid int) (*DebuggedProcess, error) {
	var (
		target DebuggedProcess
		err    error
	)
	target = DebuggedProcess{
		Process:     nil,
		Command:     "",
		Args:        nil,
		Threads:     map[int]*Thread{},
		Breakpoints: map[uintptr]*Breakpoint{},
		Kind:        ATTACH,

		once:       &sync.Once{},
		ptraceCh:   make(chan func()),
		ptraceDone: make(chan int),
		stopCh:     make(chan int),
	}
	defer func() {
		if err != nil {
			target.StopPtrace()
		}
	}()

	if target.Process, err = os.FindProcess(pid); err != nil {
		return nil, err
	}

	target.ExecPtrace(func() {
		// attach to running process (thread)
		err = target.attach(pid)
	})
	if err != nil {
		return nil, err
	}

	// initialize the command and arguments,
	// after then, we could support restart command.
	if target.Command, err = readProcComm(pid); err != nil {
		return nil, err
	}

	if target.Args, err = readProcCommArgs(pid); err != nil {
		return nil, err
	}

	target.ExecPtrace(func() {
		// attach to other threads, and prepare to trace newly created thread
		err = target.updateThreadList()
	})
	if err != nil {
		return nil, err
	}

	// load line table
	err = target.loadLineTable()
	if err != nil {
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
func (t *DebuggedProcess) launchCommand(execName string, args ...string) (*os.Process, error) {

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
	progCmd.Env = append(progCmd.Env, "GODEBUG=asyncpreemptoff=1")

	// start the process
	err := progCmd.Start()
	if err != nil {
		return nil, err
	}
	t.Process = progCmd.Process

	// wait target process stopped
	_, status, err := t.wait(progCmd.Process.Pid, syscall.WALL)
	if err != nil {
		return nil, err
	}
	fmt.Printf("process %d stopped: %v\n", progCmd.Process.Pid, status.Stopped())

	return progCmd.Process, nil
}

func (t *DebuggedProcess) loadLineTable() error {

	// open elf file
	file, err := elf.Open(fmt.Sprintf("/proc/%d/exe", t.Process.Pid))
	if err != nil {
		return err
	}

	// read elf sections
	v := file.Section(".gopclntab")
	pcln, err := v.Data()
	if err != nil {
		return err
	}

	sym, err := file.Section(".gosymtab").Data()
	if err != nil {
		return err
	}

	lntab := gosym.NewLineTable(pcln, v.Addr)
	tab, err := gosym.NewTable(sym, lntab)
	if err != nil {
		return err
	}

	t.Table = tab
	return nil
}

func (t *DebuggedProcess) ExecPtrace(fn func()) {
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

func (t *DebuggedProcess) StopPtrace() {
	close(t.stopCh)
}

// attach attach to process pid
func (t *DebuggedProcess) attach(pid int) error {

	// check traceePID
	if !checkPid(pid) {
		return fmt.Errorf("process %d not existed\n", pid)
	}

	// attach
	err := syscall.PtraceAttach(pid)
	if err != nil {
		return fmt.Errorf("process %d attached error: %v\n", pid, err)
	}
	fmt.Printf("process %d attached succ\n", pid)

	// wait
	_, status, err := t.wait(pid, syscall.WALL)
	if err != nil {
		return fmt.Errorf("process %d waited error: %v\n", pid, err)
	}
	fmt.Printf("process %d stopped: %v\n", pid, status.Stopped())
	return nil
}

func (t *DebuggedProcess) Detach() error {

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

func (t *DebuggedProcess) loadThreadList() ([]int, error) {
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

func (t *DebuggedProcess) updateThreadList() error {

	tids, err := t.loadThreadList()
	if err != nil {
		return fmt.Errorf("load threads err: %v", err)
	}

	for _, tid := range tids {
		// attach to thread
		err = syscall.PtraceAttach(tid)
		if err != nil && err != unix.EPERM {
			// Maybe we have traced tid via PTRACE_O_TRACECLONE.
			// If we try to attach to it again, it will fail.
			// We should ignore this kind of error.
			return fmt.Errorf("attach err: %v", err)
		}

		// wait thread
		_, status, err := t.wait(tid, syscall.WALL|syscall.WNOHANG)
		if err != nil {
			return fmt.Errorf("wait err: %v", err)
		}
		if status.Exited() {
			fmt.Printf("thread:%d already exited\n", tid)
		}

		// update thread
		err = syscall.PtraceSetOptions(tid, syscall.PTRACE_O_TRACECLONE)
		if err != nil {
			return fmt.Errorf("set PTRACE_O_TRACECLONE err: %v", err)
		}

		t.Threads[tid] = &Thread{
			Tid:     tid,
			Status:  *status,
			Process: t,
		}
	}
	return nil
}

// -------------------------------------------------------------------

// ProcessStart 启动被调试进程
func (t *DebuggedProcess) ProcessStart() error {
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
func (t *DebuggedProcess) ListBreakpoints() {
	for _, b := range t.Breakpoints {
		fmt.Printf("breakpoint[%d] addr:%#x, loc:%s\n", b.ID, b.Addr, b.Pos)
	}
}

// AddBreakpoint 在地址addr处添加断点，返回新创建的断点
func (t *DebuggedProcess) AddBreakpoint(addr uintptr) (*Breakpoint, error) {
	var (
		breakpoint *Breakpoint
		err        error
	)

	t.ExecPtrace(func() {
		pid := DBPProcess.Process.Pid

		orig := [1]byte{}
		n, err := syscall.PtracePeekText(pid, addr, orig[:])
		if err != nil || n != 1 {
			err = fmt.Errorf("peek text, %d bytes, error: %v", n, err)
			return
		}

		breakpoint = newBreakPoint(addr, orig[0], "")
		t.Breakpoints[addr] = breakpoint

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

var (
	ErrBreakpointNotExisted = errors.New("breakpoint not existed")
)

// ClearBreakpoint 删除addr处的断点
func (t *DebuggedProcess) ClearBreakpoint(addr uintptr) (*Breakpoint, error) {

	brk, ok := t.Breakpoints[addr]
	if !ok {
		return nil, ErrBreakpointNotExisted
	}

	// 移除断点
	pid := t.Process.Pid

	var err error
	t.ExecPtrace(func() {
		var n int
		n, err = syscall.PtracePokeData(pid, brk.Addr, []byte{brk.Orig})
		if err != nil || n != 1 {
			err = fmt.Errorf("ptrace poke data err: %v", err)
			return
		}
		delete(t.Breakpoints, brk.Addr)
	})

	return brk, nil
}

// ClearAll 删除所有已添加的断点
func (t *DebuggedProcess) ClearAll() error {
	return nil
}

func (t *DebuggedProcess) Continue() error {
	var err error
	t.ExecPtrace(func() {
		err = syscall.PtraceCont(t.Process.Pid, 0)
	})
	if err != nil {
		return err
	}

	wpid, status, err := t.wait(t.Process.Pid, syscall.WALL)
	fmt.Printf("thread %d status: %v\n", wpid, desc(status))
	return err
}

func desc(status *syscall.WaitStatus) string {
	switch {
	case status.Continued():
		return "continued"
	case status.Exited():
		return "exited: " + strconv.Itoa(status.ExitStatus())
	case status.Signaled():
		return "signaled: " + status.Signal().String()
	case status.Stopped():
		return "stopped: " + status.StopSignal().String()
	case status.CoreDump():
		return "coredump"
	default:
		return strconv.Itoa(int(*status))
	}
}

// ContinueX 执行到下一个断点处，考虑所有线程的问题
func (t *DebuggedProcess) ContinueX() error {

	var err error
	for _, thread := range t.Threads {
		t.ExecPtrace(func() {
			// continue
			err = syscall.PtraceCont(thread.Tid, 0)
			if err != nil {
				fmt.Printf("thread: %d ptrace cont, err: %v\n", thread.Tid, err)
			}
		})

		// wait, if there's no children threads, return immediately
		wpid, status, err := t.wait(thread.Tid, 0)
		if err != nil {
			return fmt.Errorf("thread: %d wait, err: %v", thread.Tid, err)
		}

		if wpid == 0 {
			continue
		}

		// new cloned thread
		if !(status.StopSignal() == syscall.SIGTRAP && status.TrapCause() == syscall.PTRACE_EVENT_CLONE) {
			continue
		}

		// A traced thread has cloned a new thread, grab the pid and
		// add it to our list of traced threads.
		var cloned uint
		t.ExecPtrace(func() {
			cloned, err = syscall.PtraceGetEventMsg(wpid)
		})
		if err != nil {
			if err == syscall.ESRCH {
				// thread died while we were adding it
				continue
			}
			return fmt.Errorf("could not get event message: %s", err)
		}

		t.ExecPtrace(func() {
			err = syscall.PtraceSetOptions(int(cloned), syscall.PTRACE_O_TRACECLONE)
		})
		if err != nil {
			return err
		}

		t.Threads[int(cloned)] = &Thread{
			Tid:     int(cloned),
			Status:  *status,
			Process: t,
		}
	}

	return err
}

// SingleStep 执行一条指令
func (t *DebuggedProcess) SingleStep() (*syscall.WaitStatus, error) {
	var err error
	t.ExecPtrace(func() {
		err = syscall.PtraceSingleStep(t.Process.Pid)
	})
	if err != nil {
		return nil, err
	}

	// MUST: 当发起了某些对tracee执行控制的ptrace request之后，要调用syscall.Wait等待并获取tracee状态变化
	var (
		wstatus syscall.WaitStatus
		rusage  syscall.Rusage
		pid     = t.Process.Pid
	)
	_, err = syscall.Wait4(pid, &wstatus, syscall.WALL, &rusage)
	if err != nil {
		return nil, fmt.Errorf("wait error: %v", err)
	}

	return &wstatus, nil
}

// --------------------------------------------------------------------

// Disassemble 反汇编地址addr处的指令
func (t *DebuggedProcess) Disassemble(addr, max uint64, syntax string) error {

	// 指令数据
	dat := make([]byte, 1024)
	n, err := t.ReadMemory(uintptr(addr), dat)
	if err != nil || n == 0 {
		return fmt.Errorf("peek text error: %v, bytes: %d", err, n)
	}

	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 8, ' ', 0)

	// 反汇编这里的指令数据
	offset := uint64(0)
	count := uint64(0)

	for count < max {
		inst, err := x86asm.Decode(dat[offset:], 64)
		if err != nil {
			return fmt.Errorf("x86asm decode error: %v", err)
		}

		asm, err := instSyntax(inst, syntax)
		if err != nil {
			return fmt.Errorf("x86asm syntax error: %v", err)
		}

		end := offset + uint64(inst.Len)
		fmt.Fprintf(tw, "%#x:\t% x\t%s\n", addr+offset, dat[offset:end], asm)
		offset = end
		count++
	}
	tw.Flush()

	return nil
}

func instSyntax(inst x86asm.Inst, syntax string) (string, error) {
	asm := ""
	switch syntax {
	case "go":
		asm = x86asm.GoSyntax(inst, uint64(inst.PCRel), nil)
	case "gnu":
		asm = x86asm.GNUSyntax(inst, uint64(inst.PCRel), nil)
	case "intel":
		asm = x86asm.IntelSyntax(inst, uint64(inst.PCRel), nil)
	default:
		return "", fmt.Errorf("invalid asm syntax error")
	}
	return asm, nil
}

// --------------------------------------------------------------------

// ReadMemory 读取内存地址addr处的数据，并存储到buf中，函数返回实际读取的字节数
func (t *DebuggedProcess) ReadMemory(addr uintptr, buf []byte) (int, error) {
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
func (t *DebuggedProcess) WriteMemory(addr uintptr, value []byte) error {
	return nil
}

// ReadRegister 读取寄存器的数据
func (t *DebuggedProcess) ReadRegister() (*syscall.PtraceRegs, error) {
	var (
		regs syscall.PtraceRegs
		err  error
	)

	t.ExecPtrace(func() {
		pid := t.Process.Pid
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
func (t *DebuggedProcess) WriteRegister(regs *syscall.PtraceRegs) error {
	var err error
	t.ExecPtrace(func() {
		pid := t.Process.Pid
		err = syscall.PtraceSetRegs(pid, regs)
	})
	return err
}

// --------------------------------------------------------------------

// Backtrace 获取调用栈信息
func (t *DebuggedProcess) Backtrace() ([]byte, error) {
	return nil, nil
}

// Frame 返回${idx}th个栈帧的信息
func (t *DebuggedProcess) Frame(idx int) error {
	return nil
}

func (t *DebuggedProcess) wait(pid, options int) (int, *syscall.WaitStatus, error) {
	var s syscall.WaitStatus
	if (t.Process.Pid != pid) || (options != 0) {
		wpid, err := syscall.Wait4(pid, &s, syscall.WALL|options, nil)
		return wpid, &s, err
	}
	// If we call wait4/waitpid on a thread that is the leader of its group,
	// with options == 0, while ptracing and the thread leader has exited leaving
	// zombies of its own then waitpid hangs forever this is apparently intended
	// behaviour in the linux kernel because it's just so convenient.
	// Therefore we call wait4 in a loop with WNOHANG, sleeping a while between
	// calls and exiting when either wait4 succeeds or we find out that the thread
	// has become a zombie.
	// References:
	// https://sourceware.org/bugzilla/show_bug.cgi?id=12702
	// https://sourceware.org/bugzilla/show_bug.cgi?id=10095
	// https://sourceware.org/bugzilla/attachment.cgi?id=5685
	for {
		wpid, err := syscall.Wait4(pid, &s, syscall.WNOHANG|syscall.WALL|options, nil)
		if err != nil {
			return 0, nil, err
		}
		if wpid != 0 {
			return wpid, &s, err
		}
		if status(pid, t.Command) == statusZombie {
			return pid, nil, nil
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func status(pid int, comm string) rune {
	f, err := os.Open(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return '\000'
	}
	defer f.Close()
	rd := bufio.NewReader(f)

	var (
		p     int
		state rune
	)

	// The second field of /proc/pid/stat is the name of the task in parenthesis.
	// The name of the task is the base name of the executable for this process limited to TASK_COMM_LEN characters
	// Since both parenthesis and spaces can appear inside the name of the task and no escaping happens we need to read the name of the executable first
	// See: include/linux/sched.c:315 and include/linux/sched.c:1510
	_, _ = fmt.Fscanf(rd, "%d ("+comm+")  %c", &p, &state)
	return state
}

// Process statuses
const (
	statusSleeping  = 'S'
	statusRunning   = 'R'
	statusTraceStop = 't'
	statusZombie    = 'Z'

	// Kernel 2.6 has TraceStop as T
	// TODO(derekparker) Since this means something different based on the
	// version of the kernel ('T' is job control stop on modern 3.x+ kernels) we
	// may want to differentiate at some point.
	statusTraceStopT = 'T'

	personalityGetPersonality = 0xffffffff // argument to pass to personality syscall to get the current personality
	_ADDR_NO_RANDOMIZE        = 0x0040000  // ADDR_NO_RANDOMIZE linux constant
)
