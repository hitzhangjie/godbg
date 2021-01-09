package debug

import (
	"errors"
	"fmt"

	"github.com/hitzhangjie/godbg/target"

	"github.com/spf13/cobra"
)

var clearCmd = &cobra.Command{
	Use:   "clear <breakpoint no.>",
	Short: "清除指定编号的断点",
	Long:  `清除指定编号的断点`,
	Annotations: map[string]string{
		cmdGroupAnnotation: cmdGroupBreakpoints,
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		//fmt.Printf("clear %s\n", strings.Join(args, " "))
		id, err := cmd.Flags().GetUint64("n")
		if err != nil {
			return err
		}

		// 查找断点
		var brk *target.Breakpoint
		for _, b := range target.DebuggedProcess.Breakpoints {
			if b.ID != id {
				continue
			}
			brk = b
			break
		}

		if brk == nil {
			return errors.New("断点不存在")
		}

		// 移除断点
		_, err = target.DebuggedProcess.ClearBreakpoint(brk.Addr)
		if err != nil {
			return err
		}
		fmt.Println("移除断点成功")
		return nil
	},
}

func init() {
	debugRootCmd.AddCommand(clearCmd)

	clearCmd.Flags().Uint64P("n", "n", 1, "断点编号")
}
