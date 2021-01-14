package debug

import (
	"fmt"

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
	RunE: func(cmd *cobra.Command, args []string) (err error) {

		dbp := target.DebuggedProcess
		defer func() {
			if err != nil {
				return
			}
			// display current pc
			regs, err := target.DebuggedProcess.ReadRegister()
			if err != nil {
				fmt.Printf("get regs error: %v", err)
			}
			fmt.Printf("continue ok, current PC: %#x\n", regs.PC())
		}()

		// 读取PC值
		regs, err := dbp.ReadRegister()
		if err != nil {
			return fmt.Errorf("get regs error: %v", err)
		}
		fmt.Printf("pc value: %#x\n", regs.PC())

		buf := make([]byte, 1)
		n, err := dbp.ReadMemory(uintptr(regs.PC()-1), buf)
		if err != nil || n != 1 {
			return fmt.Errorf("peek text error: %v, bytes: %d", err, n)
		}
		fmt.Printf("pc-1 data: %#x\n", buf[0])

		// not a breakpoint
		if buf[0] != 0xcc {
			return dbp.Continue()
		}

		// read a breakpoint
		fmt.Printf("ready to clear %#x\n", regs.PC()-1)

		brk, err := dbp.ClearBreakpoint(uintptr(regs.PC() - 1))
		if err != nil {
			// inner error occur
			if err != target.ErrBreakpointNotExisted {
				return fmt.Errorf("clear breakpoint err: %v", err)
			}
			// this 0xcc is not patched by debugger, and this 0xcc has been executed already,
			// so just continue
			return dbp.Continue()
		}
		defer dbp.AddBreakpoint(brk.Addr)

		// rewind 1 byte
		regs.SetPC(regs.PC() - 1)
		if err = dbp.WriteRegister(regs); err != nil {
			return err
		}

		if err = dbp.Continue(); err != nil {
			return fmt.Errorf("continue error: %v", err)
		}
		fmt.Println("continue ok")

		return nil
	},
}

func init() {
	debugRootCmd.AddCommand(continueCmd)
}
