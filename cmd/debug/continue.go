package debug

import (
	"fmt"
	"syscall"

	"github.com/hitzhangjie/godbg/target"
	"github.com/spf13/cobra"
)

var continueCmd = &cobra.Command{
	Use:   "continue",
	Short: "运行到下个断点",
	Annotations: map[string]string{
		cmdGroupAnnotation: cmdGroupCtrlFlow,
	},
	Aliases: []string{"c"},
	RunE: func(cmd *cobra.Command, args []string) error {
		//fmt.Println("continue")
		pid := target.DebuggedProcess.Process.Pid
		// 读取PC值
		regs, err := target.DebuggedProcess.ReadRegister()
		if err != nil {
			return fmt.Errorf("get regs error: %v", err)
		}

		buf := make([]byte, 1)
		n, err := target.DebuggedProcess.ReadMemory(uintptr(regs.PC()), buf)
		if err != nil || n != 1 {
			return fmt.Errorf("peek text error: %v, bytes: %d", err, n)
		}

		// read a breakpoint
		if buf[0] == 0xCC {

			brk, err := target.DebuggedProcess.ClearBreakpoint(uintptr(regs.PC()))
			if err != nil {
				return fmt.Errorf("清除断点失败")
			}
			defer target.DebuggedProcess.AddBreakpoint(brk.Addr)

			// rewind 1 byte
			regs.SetPC(regs.PC() - 1)
			err = target.DebuggedProcess.WriteRegister(regs)
			if err != nil {
				return err
			}
		}

		err = target.DebuggedProcess.Continue()
		if err != nil {
			return fmt.Errorf("continue error: %v", err)
		}

		// MUST: 当发起了某些对tracee执行控制的ptrace request之后，要调用syscall.Wait等待并获取tracee状态变化
		var (
			wstatus syscall.WaitStatus
			rusage  syscall.Rusage
		)
		_, err = syscall.Wait4(pid, &wstatus, syscall.WALL, &rusage)
		if err != nil {
			return fmt.Errorf("wait error: %v", err)
		}

		// display current pc
		regs, err = target.DebuggedProcess.ReadRegister()
		if err != nil {
			return fmt.Errorf("get regs error: %v", err)
		}
		fmt.Printf("continue ok, current PC: %#x\n", regs.PC())
		return nil
	},
}

func init() {
	debugRootCmd.AddCommand(continueCmd)
}
