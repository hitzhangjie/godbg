package debug

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/hitzhangjie/godbg/pkg/target"
	"github.com/spf13/cobra"
)

var breakCmd = &cobra.Command{
	Use:   "break <locspec>",
	Short: "在源码中添加断点",
	Long: `在源码中添加断点，源码位置可以通过locspec格式指定。

当前支持的locspec格式，包括两种:
- 指令地址
- [文件名:]行号
- [文件名:]函数名`,
	Aliases: []string{"b", "breakpoint"},
	Annotations: map[string]string{
		cmdGroupAnnotation: cmdGroupBreakpoints,
	},
	RunE: func(cmd *cobra.Command, args []string) error {

		if len(args) != 1 {
			return errors.New("参数错误")
		}

		var (
			addr uint64
			err  error
		)

		locStr := args[0]

		// try parse as address
		{
			addr, err = parseAddress(locStr)
			if err == nil {
				goto ADD_BREAKPOINT
			}
		}

		// try parse as file:lineno
		{
			// not supported
		}

	ADD_BREAKPOINT:
		// target add breakpoint
		_, err = target.DBPProcess.AddBreakpoint(uintptr(addr))
		if err != nil {
			return err
		}
		return nil
	},
}

func init() {
	debugRootCmd.AddCommand(breakCmd)
}

func parseAddress(locStr string) (uint64, error) {
	v, err := strconv.ParseUint(locStr, 0, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid locspec: %v", err)
	}
	return v, nil
}
