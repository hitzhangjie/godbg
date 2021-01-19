package debug

import (
	"errors"

	"github.com/hitzhangjie/godbg/pkg/target"
	"github.com/spf13/cobra"
)

var printCmd = &cobra.Command{
	Use:     "print <var|reg>",
	Short:   "打印变量或寄存器值",
	Aliases: []string{"p"},
	Annotations: map[string]string{
		cmdGroupAnnotation: cmdGroupInfo,
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return errors.New("need variable name")
		}
		return target.DBPProcess.PrintVariable(args[0])
	},
}

func init() {
	debugRootCmd.AddCommand(printCmd)
}
