package debug

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/hitzhangjie/godbg/target"
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
		//fmt.Printf("break %s\n", strings.Join(args, " "))
		if len(args) != 1 {
			return errors.New("参数错误")
		}

		locStr := args[0]
		v, err := strconv.ParseUint(locStr, 0, 64)
		if err != nil {
			return fmt.Errorf("invalid locspec: %v", err)
		}
		addr := uintptr(v)

		_, err = target.DebuggedProcess.AddBreakpoint(addr)
		if err != nil {
			return err
		}
		fmt.Printf("添加断点成功\n")
		return nil
	},
}

func init() {
	debugRootCmd.AddCommand(breakCmd)
}
