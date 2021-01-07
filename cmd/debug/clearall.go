package debug

import (
	"fmt"
	"syscall"

	"github.com/hitzhangjie/godbg/target"

	"github.com/spf13/cobra"
)

var clearallCmd = &cobra.Command{
	Use:   "clearall",
	Short: "清除所有的断点",
	Long:  `清除所有的断点`,
	Annotations: map[string]string{
		cmdGroupAnnotation: cmdGroupBreakpoints,
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		//fmt.Println("clearall")
		pid := target.DebuggedProcess.Process.Pid
		for _, brk := range breakpoints {
			n, err := syscall.PtracePokeData(pid, brk.Addr, []byte{brk.Orig})
			if err != nil || n != 1 {
				return fmt.Errorf("清空断点失败: %v", err)
			}
		}

		breakpoints = map[uintptr]*target.Breakpoint{}
		fmt.Println("清空断点成功")
		return nil
	},
}

func init() {
	debugRootCmd.AddCommand(clearallCmd)
}
