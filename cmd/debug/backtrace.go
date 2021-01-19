package debug

import (
	"github.com/hitzhangjie/godbg/pkg/target"
	"github.com/spf13/cobra"
)

var backtraceCmd = &cobra.Command{
	Use:     "bt",
	Short:   "打印调用栈信息",
	Aliases: []string{"backtrace"},
	Annotations: map[string]string{
		cmdGroupAnnotation: cmdGroupInfo,
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		return target.DBPProcess.BacktraceX()
	},
}

func init() {
	debugRootCmd.AddCommand(backtraceCmd)
}
