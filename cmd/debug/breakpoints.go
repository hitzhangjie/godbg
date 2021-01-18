package debug

import (
	"fmt"
	"sort"

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
	RunE: func(cmd *cobra.Command, args []string) error {
		bs := target.Breakpoints{}
		for _, b := range target.DBPProcess.Breakpoints {
			bs = append(bs, b)
		}
		sort.Sort(bs)

		for _, b := range bs {
			fmt.Printf("breakpoint[%d] %#x %s\n", b.ID, b.Addr, b.Pos)
		}
		return nil
	},
}

func init() {
	debugRootCmd.AddCommand(breaksCmd)
}
