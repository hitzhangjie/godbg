package debug

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/hitzhangjie/godbg/pkg/target"
	"github.com/spf13/cobra"
)

var setMemCmd = &cobra.Command{
	Use:   "setmem <addr> <value>",
	Short: "设置指定内存位置的值",
	Annotations: map[string]string{
		cmdGroupAnnotation: cmdGroupInfo,
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		// 检查参数数量
		if len(args) != 2 {
			return errors.New("usage: setmem <addr> <value>")
		}

		// 检查是否有调试进程
		if target.DBPProcess == nil {
			return errors.New("please attach to a process first")
		}

		// 解析地址参数
		addrStr := args[0]
		addr, err := strconv.ParseUint(addrStr, 0, 64)
		if err != nil {
			return fmt.Errorf("invalid address format: %s", addrStr)
		}

		// 解析值参数
		valueStr := args[1]
		value, err := strconv.ParseUint(valueStr, 0, 64)
		if err != nil {
			return fmt.Errorf("invalid value format: %s", valueStr)
		}

		// 读取当前内存值用于显示
		var oldData [1]byte
		n, err := target.DBPProcess.ReadMemory(uintptr(addr), oldData[:])
		if err != nil || n != 1 {
			return fmt.Errorf("failed to read memory at address 0x%x: %v", addr, err)
		}

		// 写入新值
		newData := []byte{byte(value)}
		err = target.DBPProcess.WriteMemory(uintptr(addr), newData)
		if err != nil {
			return fmt.Errorf("failed to write memory at address 0x%x: %v", addr, err)
		}

		// 显示操作结果
		return nil
	},
}

func init() {
	debugRootCmd.AddCommand(setMemCmd)
}
