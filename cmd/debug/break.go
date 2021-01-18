package debug

import (
	"errors"
	"fmt"
	"path/filepath"
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
		//fmt.Printf("break %s\n", strings.Join(args, " "))
		if len(args) != 1 {
			return errors.New("参数错误")
		}

		var (
			addr uint64
			err  error
		)

		// try parse as address
		locStr := args[0]
		{
			addr, err = parseAddress(locStr)
			if err == nil {
				goto BREAK
			}
		}

		// try parse as file:lineno
		{
			file, lineno, err := parseFileLineno(locStr)
			if err != nil {
				return fmt.Errorf("invalid loc: %s", locStr)
			}
			file, err = filepath.Abs(file)
			if err != nil {
				return err
			}

			pc, err := target.DBPProcess.BInfo.FileLineToPC(file, lineno)
			if err != nil {
				return fmt.Errorf("fileline to pc err: %v", err)
			}
			fmt.Printf("line table get addr: %#x\n", pc)
		}

	BREAK:
		// target add breakpoint
		_, err = target.DBPProcess.AddBreakpoint(uintptr(addr))
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

func parseAddress(locStr string) (uint64, error) {
	v, err := strconv.ParseUint(locStr, 0, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid locspec: %v", err)
	}
	return v, nil
}
