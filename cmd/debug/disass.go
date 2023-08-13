package debug

import (
	"fmt"

	"github.com/hitzhangjie/godbg/pkg/target"
	"github.com/spf13/cobra"
)

var disassCmd = &cobra.Command{
	Use:   "disass [address]",
	Short: "反汇编机器指令",
	Annotations: map[string]string{
		cmdGroupAnnotation: cmdGroupSource,
	},
	Aliases: []string{"dis", "disassemble"},
	RunE: func(cmd *cobra.Command, args []string) error {
		var (
			max, _    = cmd.Flags().GetUint64("max")
			syntax, _ = cmd.Flags().GetString("syntax")
		)
		// 读取PC值
		regs, err := target.DBPProcess.ReadRegister()
		if err != nil {
			return err
		}
		addr := regs.PC()

		// 检测addr处是否为断点
		buf := make([]byte, 1)
		n, err := target.DBPProcess.ReadMemory(uintptr(addr-1), buf)
		if err != nil || n != 1 {
			return fmt.Errorf("peek text error: %v, bytes: %d", err, n)
		}

		// read a breakpoint
		if buf[0] == 0xcc {
			brk, err := target.DBPProcess.ClearBreakpoint(uintptr(addr - 1))
			if err == target.ErrBreakpointNotExisted {
				// this 0xcc is not patched by debugger, decode from `addr`
				return target.DBPProcess.Disassemble(addr, max, syntax)
			}
			if err != nil {
				// debugger inner error
				return fmt.Errorf("clear breakpoint err: %v", err)
			}
			defer target.DBPProcess.AddBreakpoint(brk.Addr)

			// rewind 1 byte
			regs.SetPC(regs.PC() - 1)
			if err = target.DBPProcess.WriteRegister(regs); err != nil {
				return err
			}
		}

		// disassemble instructions
		return target.DBPProcess.Disassemble(addr, max, syntax)
	},
}

func init() {
	debugRootCmd.AddCommand(disassCmd)

	disassCmd.Flags().Uint64P("max", "n", 10, "反汇编指令数量")
	disassCmd.Flags().StringP("syntax", "s", "gnu", "反汇编指令语法，支持：go, gnu, intel")
}
