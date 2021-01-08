package target

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"syscall"
)

var (
	DebuggedProcess *TargetProcess
)

// TargetProcess 被调试进程信息
type TargetProcess struct {
	Process     *os.Process // 进程信息
	Command     string      // 进程启动命令，方便重启调试
	Args        []string    // 进程启动参数，方便重启调试
	Threads     []Thread    // 包含的线程列表
	Breakpoints Breakpoints // 已经添加的断点
}

// NewTargetProcess 创建一个待调试进程
func NewTargetProcess(cmd string, args ...string) (*TargetProcess, error) {
	target := TargetProcess{
		Process:     nil,
		Command:     cmd,
		Args:        args,
		Threads:     []Thread{},
		Breakpoints: Breakpoints{},
	}

	p, err := executeCommand(cmd, args...)
	if err != nil {
		return nil, err
	}
	target.Process = p

	return &target, nil
}

// AttachTargetProcess trace一个目标进程（准确地说是线程）
func AttachTargetProcess(pid int) (*TargetProcess, error) {
	target := TargetProcess{
		Process:     nil,
		Command:     "",
		Args:        nil,
		Threads:     []Thread{},
		Breakpoints: Breakpoints{},
	}

	err := attach(pid)
	if err != nil {
		return nil, err
	}

	p, err := os.FindProcess(pid)
	if err != nil {
		return nil, err
	}
	target.Process = p

	target.Command, err = readProcComm(pid)
	if err != nil {
		return nil, err
	}

	target.Args, err = readProcCommArgs(pid)
	if err != nil {
		return nil, err
	}

	return &target, nil
}

// readProcComm read /proc/pid/comm or /proc/pid/stat to load the command line of process.
func readProcComm(pid int) (string, error) {
	comm, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err == nil {
		// removes newline character
		comm = bytes.TrimSuffix(comm, []byte("\n"))
	}

	if comm == nil || len(comm) <= 0 {
		stat, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if err != nil {
			return "", fmt.Errorf("could not read proc stat: %v", err)
		}
		expr := fmt.Sprintf("%d\\s*\\((.*)\\)", pid)
		rexp, err := regexp.Compile(expr)
		if err != nil {
			return "", fmt.Errorf("regexp compile error: %v", err)
		}
		match := rexp.FindSubmatch(stat)
		if match == nil {
			return "", fmt.Errorf("no match found using regexp '%s' in /proc/%d/stat", expr, pid)
		}
		comm = match[1]
	}

	cmdStr := strings.ReplaceAll(string(comm), "%", "%%")
	return cmdStr, nil
}

// readProcCommArgs read /proc/pid/cmdline to load the command arguments of process
func readProcCommArgs(pid int) ([]string, error) {
	dat, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return nil, err
	}
	args := strings.Split(string(dat), string([]byte{0}))[1:]
	return args, nil
}

// executeCommand execute `execName` with `args`
func executeCommand(execName string, args ...string) (*os.Process, error) {

	progCmd := exec.Command(execName, args...)
	progCmd.Stdin = os.Stdin
	progCmd.Stdout = os.Stdout
	progCmd.Stderr = os.Stderr

	progCmd.SysProcAttr = &syscall.SysProcAttr{
		Ptrace:     true,
		Setpgid:    true,
		Foreground: false,
	}
	progCmd.Env = os.Environ()

	// note:
	// - 启动时设置了PTRACEME，不需要设置环境变量GOMAXPROCS=1
	// - 如果是attach的话，也不能保证tracee启动时有使用GOMAXPROCS=1，需要枚举线程列表attach
	//progCmd.Env = append(progCmd.Env, "GOMAXPROCS=1")

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

// attach attach to process pid
func attach(pid int) error {

	// check traceePID
	if !checkPid(int(pid)) {
		return fmt.Errorf("process %d not existed\n", pid)
	}

	// attach
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
	return nil, nil
}

// ClearBreakpoint 删除编号为id的断点，会返回id对应的断点
func (t *TargetProcess) ClearBreakpoint(id uintptr) (*Breakpoint, error) {
	return nil, nil
}

// ClearAll 删除所有已添加的断点
func (t *TargetProcess) ClearAll() error {
	return nil
}

// Continue 执行到下一个断点处
func (t *TargetProcess) Continue() error {
	return nil
}

// --------------------------------------------------------------------

// Disassemble 反汇编地址addr处的指令
func (t *TargetProcess) Disassemble(addr uintptr) ([]byte, error) {
	return nil, nil
}

// --------------------------------------------------------------------

// ReadMemory 读取内存地址addr处的size字节数据
func (t *TargetProcess) ReadMemory(addr uintptr, size int) ([]byte, error) {
	return nil, nil
}

// SetVariable 设置内存地址addr处的值为value
func (t *TargetProcess) WriteMemory(addr uintptr, value []byte) error {
	return nil
}

// ReadRegister 读取寄存器reg的数据
func (t *TargetProcess) ReadRegister(reg int) ([]byte, error) {
	return nil, nil
}

// WriteRegister 设置寄存器reg的值为value
func (t *TargetProcess) WriteRegister(reg int, value []byte) error {
	return nil
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
