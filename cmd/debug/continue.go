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
				fmt.Printf("get regs error: %v\n", err)
			}
			fmt.Printf("continue ok, current PC: %#x\n", regs.PC())
		}()

		// 读取PC值
		regs, err := dbp.ReadRegister()
		if err != nil {
			return fmt.Errorf("get regs error: %v", err)
		}

		ok, err := dbp.IsBreakpoint(uintptr(regs.PC() - 1))
		if err != nil {
			return fmt.Errorf("test breakpoint err: %v", err)
		}

		// not a breakpoint
		if !ok {
			return dbp.ContinueX()
		}

		// read a breakpoint
		brk, err := dbp.ClearBreakpoint(uintptr(regs.PC() - 1))
		if err == target.ErrBreakpointNotExisted {
			// this 0xcc is not patched by debugger, and this 0xcc has been executed already,
			// so just continue
			return dbp.ContinueX()
		}
		if err != nil {
			// inner error occur
			return fmt.Errorf("clear breakpoint err: %v", err)
		}
		defer dbp.AddBreakpoint(brk.Addr)

		// rewind 1 byte
		regs.SetPC(regs.PC() - 1)
		if err = dbp.WriteRegister(regs); err != nil {
			return err
		}

		if _, err = dbp.SingleStep(); err != nil {
			return fmt.Errorf("singlestep err: %v", err)
		}

		if err = dbp.ContinueX(); err != nil {
			return fmt.Errorf("continue error: %v", err)
		}
		fmt.Println("continue ok")

		return nil
	},
}

func init() {
	debugRootCmd.AddCommand(continueCmd)
}
