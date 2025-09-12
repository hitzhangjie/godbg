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
			max, _      = cmd.Flags().GetUint64("max")
			syntax, _   = cmd.Flags().GetString("syntax")
			clearall, _ = cmd.Flags().GetBool("clearall")
		)
		// 读取PC值
		dbp := target.DBPProcess
		regs, err := dbp.ReadRegister(dbp.Process.Pid)
		if err != nil {
			return err
		}
		addr := regs.PC()

		if len(args) == 1 {
			addr, err = parseAddress(args[0])
			if err != nil {
				return fmt.Errorf("parse address err: %v", err)
			}
		}

		// 根据选项选择不同的反汇编方式
		if clearall {
			// 新逻辑：处理断点
			return target.DBPProcess.DisassembleWithBreakpointCleared(addr, max, syntax)
		} else {
			// 老逻辑：只处理目标地址处的断点，后续的断点不处理
			return target.DBPProcess.Disassemble(addr, max, syntax)
		}
	},
}

func init() {
	debugRootCmd.AddCommand(disassCmd)

	disassCmd.Flags().Uint64P("max", "n", 10, "反汇编指令数量")
	disassCmd.Flags().StringP("syntax", "s", "gnu", "反汇编指令语法，支持：go, gnu, intel")
	disassCmd.Flags().Bool("clearall", false, "是否在反汇编时排除已有断点影响")
}
