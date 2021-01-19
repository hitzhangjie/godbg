package debug

import (
	"github.com/hitzhangjie/godbg/pkg/target"
	"github.com/spf13/cobra"
)

var breaksCmd = &cobra.Command{
	Use:     "breaks",
	Short:   "列出所有断点",
	Long:    "列出所有断点",
	Aliases: []string{"bs", "breakpoints"},
	Annotations: map[string]string{
		cmdGroupAnnotation: cmdGroupBreakpoints,
	},
	Run: func(cmd *cobra.Command, args []string) {
		target.DBPProcess.ListBreakpoints()
	},
}

func init() {
	debugRootCmd.AddCommand(breaksCmd)
}
