package target

import (
	"bufio"
	"bytes"
	"debug/elf"
	"debug/gosym"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"syscall"
	"text/tabwriter"
	"time"

	"golang.org/x/arch/x86/x86asm"
)

var DBPProcess *DebuggedProcess

// DebuggedProcess 被调试进程信息
type DebuggedProcess struct {
	Process *os.Process     // 进程信息
	Threads map[int]*Thread // 包含的线程列表,k=tid,v=thread

	Command string   // 进程启动命令，方便重启调试
	Args    []string // 进程启动参数，方便重启调试
	Kind    Kind     // 发起调试的类型

	// BInfo *symbol.BinaryInfo // 符号层操作

	Breakpoints map[uintptr]*Breakpoint // 已经添加的断点

	once   *sync.Once
	reqCh  chan ptraceRequest // ptrace请求统一发送到这里，由专门协程处理
	doneCh chan int           // 通知需要停止调试
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
		reqCh:       make(chan ptraceRequest, 16),
		doneCh:      make(chan int),
	}
	defer func() {
		if err != nil {
			target.StopPtrace()
		}
	}()

	err = target.ExecPtrace(func() error {
		// start and trace
		target.Process, err = target.launchCommand(cmd, args...)
		if err != nil {
			return err
		}

		// trace newly created thread
		return syscall.PtraceSetOptions(target.Process.Pid, syscall.PTRACE_O_TRACECLONE)
	})
	if err != nil {
		return nil, err
	}

	return &target, nil
}

// AttachTargetProcess trace一个目标进程（准确地说是线程）
func AttachTargetProcess(pid int) (p *DebuggedProcess, err error) {
	p = &DebuggedProcess{
		Process:     nil,
		Command:     "",
		Args:        nil,
		Threads:     map[int]*Thread{},
		Breakpoints: map[uintptr]*Breakpoint{},
		Kind:        ATTACH,

		once:   &sync.Once{},
		reqCh:  make(chan ptraceRequest, 16),
		doneCh: make(chan int),
	}
	// 在当前函数成功执行并返回p之前，不会有人调用其他ptrace操作，所以此时不需要p.StopPtrace
	// defer func() {
	// 	if err != nil {
	// 		p.StopPtrace()
	// 	}
	// }()

	if p.Process, err = os.FindProcess(pid); err != nil {
		return nil, err
	}

	// attach to running process (thread)
	if err := p.attach(pid); err != nil {
		return nil, err
	}

	// Go program has multi threads. To trace the go process, all underlying threads must be traced.

	// initialize DWARF, /proc/pid/comm, /proc/pid/cmdline
	if err := p.initialize(); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *DebuggedProcess) initialize() error {
	var err error

	// initialize the command and arguments, after then, we could support restart command.
	if p.Command, err = readProcComm(p.Process.Pid); err != nil {
		return err
	}
	if p.Args, err = readProcCommArgs(p.Process.Pid); err != nil {
		return err
	}

	// attach to other threads, and prepare to trace newly created thread
	return p.updateThreadList()
}

// launchCommand execute `execName` with `args`
//
// 为了方便调试，除了跟踪主线程，还需要考虑跟踪后续新创建的线程，linux 2.5.46中引入了以下ptrace选项，
// 通过设置该选项可以使得tracer自动跟踪新创建线程。
//
// PTRACE_O_TRACECLONE (since Linux 2.5.46)
//
//	Stop the tracee at the next clone(2) and
//	automatically start tracing the newly cloned
//	process, which will start with a SIGSTOP, or
//	PTRACE_EVENT_STOP if PTRACE_SEIZE was used.  A
//	waitpid(2) by the tracer will return a status value.
//
// see more info by `man 2 ptrace`.
func (p *DebuggedProcess) launchCommand(execName string, args ...string) (*os.Process, error) {

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
	p.Process = progCmd.Process

	// wait target process stopped
	_, status, err := p.wait(progCmd.Process.Pid, syscall.WALL)
	if err != nil {
		return nil, err
	}
	fmt.Printf("process %d stopped: %v, reason: %s\n",
		progCmd.Process.Pid, status.Stopped(), status.StopSignal().String())

	return progCmd.Process, nil
}

type ptraceRequest struct {
	fn    func() error
	errCh chan error
}

func (p *DebuggedProcess) ExecPtrace(fn func() error) error {

	p.once.Do(func() {
		go func() {
			// ensure all ptrace requests goes via the same tracer (thread)
			//
			// issue: https://github.com/golang/go/issues/7699
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()

			for {
				select {
				case req := <-p.reqCh:
					req.errCh <- req.fn()
				case <-p.doneCh:
					break
				}
			}
		}()
	})

	req := ptraceRequest{
		fn:    fn,
		errCh: make(chan error),
	}
	p.reqCh <- req
	return <-req.errCh
}

func (p *DebuggedProcess) StopPtrace() {
	close(p.doneCh)
}

// attach attach to process pid
func (p *DebuggedProcess) attach(pid int) error {

	// check traceePID
	if !checkPid(pid) {
		return fmt.Errorf("process %d not existed\n", pid)
	}

	// attach
	err := p.ExecPtrace(func() error { return syscall.PtraceAttach(pid) })
	if err != nil {
		return fmt.Errorf("process %d attached error: %v\n", pid, err)
	}
	fmt.Printf("process %d attached succ\n", pid)

	// wait
	_, status, err := p.wait(pid, syscall.WALL)
	if err != nil {
		return fmt.Errorf("process %d waited error: %v\n", pid, err)
	}
	fmt.Printf("process %d stopped: %v\n", pid, status.Stopped())
	return nil
}

func (p *DebuggedProcess) Detach() error {

	// check traceePID
	if !checkPid(p.Process.Pid) {
		return fmt.Errorf("process %d not existed\n", p.Process.Pid)
	}

	// Detach all threads
	for _, thread := range p.Threads {
		err := p.ExecPtrace(func() error {
			return syscall.PtraceDetach(thread.Tid)
		})
		if err != nil {
			return fmt.Errorf("thread %d detached error: %v\n", thread.Tid, err)
		}
		fmt.Printf("thread %d detached succ\n", thread.Tid)
	}
	return nil
}

func (p *DebuggedProcess) loadThreadList() ([]int, error) {
	threadIDs := []int{}

	tids, _ := filepath.Glob(fmt.Sprintf("/proc/%d/task/*", p.Process.Pid))
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

func (p *DebuggedProcess) updateThreadList() error {
	tids, err := p.loadThreadList()
	if err != nil {
		return fmt.Errorf("load threads err: %v", err)
	}

	for _, tid := range tids {
		//fmt.Printf("try to add thread %d to process %d\n", tid, p.Process.Pid)
		_, err := p.addThread(tid, tid != p.Process.Pid)
		if err != nil {
			return fmt.Errorf("add thread err: %v", err)
		}
		//fmt.Printf("add thread %d ok\n", tid)
	}
	return nil
}

// -------------------------------------------------------------------

// ProcessStart 启动被调试进程
func (p *DebuggedProcess) ProcessStart() error {
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

func (p *DebuggedProcess) IsBreakpoint(addr uintptr) bool {
	_, ok := p.Breakpoints[addr]
	return ok
}

// ListBreakpoints 列出所有断点
func (p *DebuggedProcess) ListBreakpoints() {

	bs := Breakpoints{}
	for _, b := range p.Breakpoints {
		bs = append(bs, b)
	}
	sort.Sort(bs)

	for _, b := range p.Breakpoints {
		fmt.Printf("breakpoint[%d] addr:%#x, loc:%s\n", b.ID, b.Addr, b.Pos)
	}
}

// AddBreakpoint 在地址addr处添加断点，返回新创建的断点
func (p *DebuggedProcess) AddBreakpoint(addr uintptr) (*Breakpoint, error) {
	var (
		breakpoint *Breakpoint
		err        error
		n          int
	)

	err = p.ExecPtrace(func() error {
		pid := DBPProcess.Process.Pid

		orig := [1]byte{}
		n, err = syscall.PtracePeekText(pid, addr, orig[:])
		if err != nil || n != 1 {
			return fmt.Errorf("peek text, pid: %d, %d bytes, error: %v", pid, n, err)
		}

		file := "unknown"
		line := 0

		breakpoint = newBreakPoint(addr, orig[0], fmt.Sprintf("%s:%d", file, line))
		p.Breakpoints[addr] = breakpoint

		n, err = syscall.PtracePokeText(pid, addr, []byte{0xCC})
		if err != nil || n != 1 {
			return fmt.Errorf("poke text, pid:%d, %d bytes, error: %v", pid, n, err)
		}
		return nil
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
func (p *DebuggedProcess) ClearBreakpoint(addr uintptr) (*Breakpoint, error) {

	brk, ok := p.Breakpoints[addr]
	if !ok {
		return nil, ErrBreakpointNotExisted
	}

	// 移除断点
	pid := p.Process.Pid

	err := p.ExecPtrace(func() error {
		n, err := syscall.PtracePokeData(pid, brk.Addr, []byte{brk.Orig})
		if err != nil || n != 1 {
			return fmt.Errorf("ptrace poke data err: %v", err)
		}
		delete(p.Breakpoints, brk.Addr)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return brk, nil
}

// ClearAll 删除所有已添加的断点
func (p *DebuggedProcess) ClearAll() error {
	err := p.ExecPtrace(func() error {
		for _, b := range p.Breakpoints {
			_, err := p.ClearBreakpoint(b.Addr)
			if err != nil {
				return fmt.Errorf("clear breakpoint %d, err: %v", b.Addr, err)
			}
		}
		return nil
	})
	return err
}

func (p *DebuggedProcess) Continue() error {
	err := p.ExecPtrace(func() error {
		return syscall.PtraceCont(p.Process.Pid, 0)
	})
	if err != nil {
		return err
	}

	wpid, status, err := p.wait(p.Process.Pid, syscall.WALL)
	fmt.Printf("thread %d status: %v\n", wpid, descStatus(status))
	return err
}

func descStatus(status *syscall.WaitStatus) string {
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
func (p *DebuggedProcess) ContinueX() error {

	var err error
	for _, thread := range p.Threads {
		err := p.ExecPtrace(func() error {
			// continue
			return syscall.PtraceCont(thread.Tid, 0)
		})
		if err != nil {
			return fmt.Errorf("continue thread fail: %v", err)
		}

		// wait, if there's no children threads, return immediately
		wpid, status, err := p.wait(thread.Tid, 0)
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
		err = p.ExecPtrace(func() error {
			cloned, err = syscall.PtraceGetEventMsg(wpid)
			return err
		})
		if err != nil {
			if err == syscall.ESRCH {
				// thread died while we were adding it
				continue
			}
			return fmt.Errorf("could not get event message: %s", err)
		}

		err = p.ExecPtrace(func() error { return syscall.PtraceSetOptions(int(cloned), syscall.PTRACE_O_TRACECLONE) })
		if err != nil {
			return err
		}

		p.Threads[int(cloned)] = &Thread{
			Tid:     int(cloned),
			Process: p,
		}
	}
	return err
}

// SingleStep 执行一条指令
func (p *DebuggedProcess) SingleStep() (*syscall.WaitStatus, error) {
	err := p.ExecPtrace(func() error {
		return syscall.PtraceSingleStep(p.Process.Pid)
	})
	if err != nil {
		return nil, err
	}

	// MUST: 当发起了某些对tracee执行控制的ptrace request之后，要调用syscall.Wait等待并获取tracee状态变化
	var (
		wstatus syscall.WaitStatus
		rusage  syscall.Rusage
		pid     = p.Process.Pid
	)
	_, err = syscall.Wait4(pid, &wstatus, syscall.WALL, &rusage)
	if err != nil {
		return nil, fmt.Errorf("wait error: %v", err)
	}

	return &wstatus, nil
}

// --------------------------------------------------------------------

func (p *DebuggedProcess) DisassembleSingleInstruction(addr uint64) (*x86asm.Inst, error) {

	// 指令数据
	dat := make([]byte, 16)
	n, err := p.ReadMemory(uintptr(addr), dat)
	if err != nil || n == 0 {
		return nil, fmt.Errorf("peek text error: %v, bytes: %d", err, n)
	}

	// 反汇编这里的指令数据
	inst, err := x86asm.Decode(dat, 64)
	if err != nil {
		return nil, fmt.Errorf("x86asm decode error: %v", err)
	}

	return &inst, nil
}

// Disassemble 反汇编地址addr处的指令
func (p *DebuggedProcess) Disassemble(addr, max uint64, syntax string) error {

	// 指令数据
	dat := make([]byte, 1024)
	n, err := p.ReadMemory(uintptr(addr), dat)
	if err != nil || n == 0 {
		return fmt.Errorf("peek text error: %v, bytes: %d", err, n)
	}

	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 8, ' ', 0)

	// 反汇编这里的指令数据
	offset := uint64(0)
	count := uint64(0)

	for count < max && int(offset) < n {
		inst, err := x86asm.Decode(dat[offset:], 64)
		if err != nil {
			if err == x86asm.ErrUnrecognized {
				fmt.Printf("unregonized instruction, [%0x] == %0x\n", offset, dat[offset])
				offset++
				continue
			}
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
func (p *DebuggedProcess) ReadMemory(addr uintptr, buf []byte) (int, error) {
	var (
		dat int
		err error
	)
	err = p.ExecPtrace(func() error {
		// PtracePeekText 与 PtracePeekData 效果相同
		n, err := syscall.PtracePeekText(p.Process.Pid, addr, buf)
		if err != nil {
			return err
		}
		dat = n
		return nil
	})
	return dat, err
}

// SetVariable 设置内存地址addr处的值为value
func (p *DebuggedProcess) WriteMemory(addr uintptr, value []byte) error {
	return nil
}

// ReadRegister 读取寄存器的数据
func (p *DebuggedProcess) ReadRegister() (*syscall.PtraceRegs, error) {
	var regs syscall.PtraceRegs
	err := p.ExecPtrace(func() error {
		pid := p.Process.Pid
		return syscall.PtraceGetRegs(pid, &regs)
	})
	if err != nil {
		return nil, err
	}
	return &regs, nil
}

// WriteRegister 设置寄存器reg的值为value
func (p *DebuggedProcess) WriteRegister(regs *syscall.PtraceRegs) error {
	err := p.ExecPtrace(func() error {
		pid := p.Process.Pid
		return syscall.PtraceSetRegs(pid, regs)
	})
	return err
}

// --------------------------------------------------------------------

// Backtrace 获取调用栈信息
//
// use .gopclntab, .gosymtab to build the mappings btw PC and fileLineNo,
// use regs.BP() to read the caller's BP and return address,
// then we could build the backtrace
//
// note: .gopclntab, .gosymtab only works for pure go program, not for cgo.
func (p *DebuggedProcess) Backtrace() error {

	pid := p.Process.Pid

	// 获取当前寄存器状态
	regs, err := p.ReadRegister()
	if err != nil {
		return err
	}

	// open elf file
	file, err := elf.Open(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return err
	}

	// read elf sections
	pcln, err := file.Section(".gopclntab").Data()
	if err != nil {
		return err
	}

	sym, err := file.Section(".gosymtab").Data()
	if err != nil {
		return err
	}

	lntab := gosym.NewLineTable(pcln, regs.PC())
	tab, err := gosym.NewTable(sym, lntab)
	if err != nil {
		return err
	}

	// print stack trace
	bp := regs.Rbp
	pc := regs.PC()
	idx := 0
	ret := uint64(0)

	f, n, fn := tab.PCToLine(pc - 1)
	fmt.Printf("#%d %s %s:%d\n", idx, fn.Name, f, n)

	for {
		idx++
		if bp == 0 {
			break
		}

		//addr := rbp
		buf := make([]byte, 16)

		n, err := p.ReadMemory(uintptr(bp), buf)
		if err != nil || n != 16 {
			return fmt.Errorf("read mermory err: %v, bytes: %d", err, n)
		}

		// bp of previous caller stackframe
		reader := bytes.NewBuffer(buf)
		err = binary.Read(reader, binary.LittleEndian, &bp)
		if err != nil {
			return err
		}

		// ret address
		err = binary.Read(reader, binary.LittleEndian, &ret)
		if err != nil {
			return err
		}

		// TODO：暂时不考虑内联、尾递归优化（go编译器暂时不支持尾递归优化）的话，ret基本上对应着调用方函数的栈帧，
		// 但是为了让源代码位置更精准，这里的减去对ret减1
		f, n, fn := tab.PCToLine(ret - 1)
		fmt.Printf("#%d %s %s:%d\n", idx, fn.Name, f, n)
	}
	return nil
}

// Frame 返回${idx}th个栈帧的信息
func (p *DebuggedProcess) Frame(idx int) error {
	return nil
}

func (p *DebuggedProcess) wait(pid, options int) (int, *syscall.WaitStatus, error) {
	var s syscall.WaitStatus
	if (p.Process.Pid != pid) || (options != 0) {
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
		if status(pid, p.Command) == statusZombie {
			return pid, nil, nil
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// Attach to a newly created thread, and store that thread in our list of
// known threads.
func (p *DebuggedProcess) addThread(tid int, attach bool) (*Thread, error) {
	if thread, ok := p.Threads[tid]; ok {
		return thread, nil
	}

	if attach {
		err := p.ExecPtrace(func() error { return syscall.PtraceAttach(tid) })
		if err != nil && err != syscall.EPERM {
			// Do not return err if err == EPERM,
			// we may already be tracing this thread due to
			// PTRACE_O_TRACECLONE. We will surely blow up later
			// if we truly don't have permissions.
			return nil, fmt.Errorf("could not attach to new thread %d %s", tid, err)
		}
		pid, status, err := p.waitFast(tid)
		if err != nil {
			return nil, fmt.Errorf("wait fast err: %v", err)
		}
		if status.Exited() {
			return nil, fmt.Errorf("thread already exited %d", pid)
		}
	}

	err := p.ExecPtrace(func() error {
		return syscall.PtraceSetOptions(tid, syscall.PTRACE_O_TRACECLONE)
	})

	if err == syscall.ESRCH {
		if _, _, err := p.waitFast(tid); err != nil {
			return nil, fmt.Errorf("error while waiting after adding thread: %d %s", tid, err)
		}
		err := p.ExecPtrace(func() error {
			return syscall.PtraceSetOptions(tid, syscall.PTRACE_O_TRACECLONE)
		})
		if err == syscall.ESRCH {
			return nil, err
		}
		if err != nil {
			return nil, fmt.Errorf("could not set options for new traced thread %d %s", tid, err)
		}
	}

	p.Threads[tid] = &Thread{
		Tid:     tid,
		Process: p,
	}
	return p.Threads[tid], nil
}

func (p *DebuggedProcess) waitFast(pid int) (int, *syscall.WaitStatus, error) {
	var s syscall.WaitStatus
	wpid, err := syscall.Wait4(pid, &s, syscall.WALL, nil)
	return wpid, &s, err
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
