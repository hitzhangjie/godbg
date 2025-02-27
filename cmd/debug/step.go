package debug

import (
	"fmt"

	"github.com/hitzhangjie/godbg/pkg/target"
	"github.com/spf13/cobra"
)

var stepCmd = &cobra.Command{
	Use:     "step",
	Short:   "执行一条指令",
	Aliases: []string{"s"},
	Annotations: map[string]string{
		cmdGroupAnnotation: cmdGroupCtrlFlow,
	},
	RunE: func(cmd *cobra.Command, args []string) (err error) {

		dbp := target.DBPProcess

		defer func() {
			if err != nil {
				return
			}
			// display current pc
			regs, err := dbp.ReadRegister()
			if err != nil {
				fmt.Printf("get regs error: %v", err)
				return
			}
			fmt.Printf("single step ok, current PC: %#x\n", regs.PC())
		}()

		// 读取PC值
		regs, err := dbp.ReadRegister()
		if err != nil {
			return fmt.Errorf("get regs error: %v", err)
		}

		buf := make([]byte, 1)
		n, err := dbp.ReadMemory(uintptr(regs.PC()-1), buf)
		if err != nil || n != 1 {
			return fmt.Errorf("peek text error: %v, bytes: %d", err, n)
		}

		// isn't a breakpoint
		if buf[0] != 0xcc {
			if _, err = dbp.SingleStep(); err != nil {
				return fmt.Errorf("single step err: %v", err)
			}
			return nil
		}

		// is a breakpoint
		brk, err := dbp.ClearBreakpoint(uintptr(regs.PC() - 1))
		if err == target.ErrBreakpointNotExisted {
			// this 0xcc isn't patched by debugger, and this 0xcc is already executed,
			// just single step
			_, err = dbp.SingleStep()
			return err
		}
		if err != nil {
			// debugger inner error
			return fmt.Errorf("clear breakpoint err: %v", err)
		}
		defer dbp.AddBreakpoint(brk.Addr)

		// rewind pc by 1
		regs.SetPC(regs.PC() - 1)
		if err = dbp.WriteRegister(regs); err != nil {
			return err
		}

		// single step
		if _, err = dbp.SingleStep(); err != nil {
			return fmt.Errorf("single step error: %v", err)
		}
		return nil
	},
}

func init() {
	debugRootCmd.AddCommand(stepCmd)
}
