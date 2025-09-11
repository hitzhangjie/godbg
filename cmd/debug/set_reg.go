package debug

import (
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"github.com/hitzhangjie/godbg/pkg/target"
	"github.com/spf13/cobra"
)

var setRegCmd = &cobra.Command{
	Use:   "setreg <reg> <value>",
	Short: "设置寄存器值",
	Annotations: map[string]string{
		cmdGroupAnnotation: cmdGroupInfo,
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		// 检查参数数量
		if len(args) != 2 {
			return errors.New("usage: setreg <reg> <value>")
		}

		// 检查是否有调试进程
		if target.DBPProcess == nil {
			return errors.New("please attach to a process first")
		}

		regName := strings.ToLower(args[0])
		valueStr := args[1]

		// 解析值参数
		value, err := strconv.ParseUint(valueStr, 0, 64)
		if err != nil {
			return fmt.Errorf("invalid value format: %s", valueStr)
		}

		// 读取当前寄存器状态
		regs, err := target.DBPProcess.ReadRegister()
		if err != nil {
			return fmt.Errorf("failed to read registers: %v", err)
		}

		// 使用反射设置寄存器值
		rv := reflect.ValueOf(regs).Elem()
		rt := reflect.TypeOf(*regs)

		var fieldFound bool
		for i := 0; i < rv.NumField(); i++ {
			fieldName := strings.ToLower(rt.Field(i).Name)
			if fieldName == regName {
				// 设置新值
				rv.Field(i).SetUint(value)
				fieldFound = true

				// 写回寄存器
				err = target.DBPProcess.WriteRegister(regs)
				if err != nil {
					return fmt.Errorf("failed to write register %s: %v", regName, err)
				}
				break
			}
		}

		if !fieldFound {
			return fmt.Errorf("invalid register name: %s", regName)
		}
		return nil
	},
}

func init() {
	debugRootCmd.AddCommand(setRegCmd)
}
