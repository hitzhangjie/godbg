package debug

import (
	"github.com/hitzhangjie/godbg/pkg/target"
	"github.com/spf13/cobra"
)

var nextCmd = &cobra.Command{
	Use:     "next",
	Short:   "执行一条语句",
	Aliases: []string{"n"},
	Annotations: map[string]string{
		cmdGroupAnnotation: cmdGroupCtrlFlow,
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		return target.DBPProcess.NextX()
	},
}

func init() {
	debugRootCmd.AddCommand(nextCmd)
}
