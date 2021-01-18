package debug

import (
	"fmt"

	"github.com/hitzhangjie/godbg/pkg/target"

	"github.com/spf13/cobra"
)

var clearallCmd = &cobra.Command{
	Use:   "clearall",
	Short: "清除所有的断点",
	Long:  `清除所有的断点`,
	Annotations: map[string]string{
		cmdGroupAnnotation: cmdGroupBreakpoints,
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		//fmt.Println("clearall")
		for _, brk := range target.DBPProcess.Breakpoints {
			_, err := target.DBPProcess.ClearBreakpoint(brk.Addr)
			if err != nil {
				return fmt.Errorf("清除断点%d失败\n", brk.ID)
			}
		}
		fmt.Println("清空断点成功")
		return nil
	},
}

func init() {
	debugRootCmd.AddCommand(clearallCmd)
}
