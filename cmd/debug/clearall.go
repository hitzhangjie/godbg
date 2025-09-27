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
		if err := target.DBPProcess.ClearAll(); err != nil {
			return fmt.Errorf("清除断点失败: %v", err)
		}

		fmt.Println("清空断点成功")
		return nil
	},
}

func init() {
	debugRootCmd.AddCommand(clearallCmd)
}
