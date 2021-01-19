package debug

import (
	"fmt"
	"os"

	"github.com/hitzhangjie/godbg/pkg/target"
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

		dbp := target.DBPProcess
		defer func() {
			if err != nil {
				return
			}
			// display current pc
			regs, err := target.DBPProcess.ReadRegister()
			if err != nil {
				fmt.Fprintf(os.Stderr, "get regs error: %v\n", err)
				return
			}
			fmt.Printf("continue ok, current PC: %#x\n", regs.PC())
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

		// not a breakpoint
		if buf[0] != 0xcc {
			return dbp.Continue()
		}

		// read a breakpoint
		brk, err := dbp.ClearBreakpoint(uintptr(regs.PC() - 1))
		if err == target.ErrBreakpointNotExisted {
			// this 0xcc is not patched by debugger, and this 0xcc has been executed already,
			// so just continue
			return dbp.Continue()
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
