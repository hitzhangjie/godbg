package debug

import (
	"fmt"
	"os"

	"github.com/hitzhangjie/godbg/pkg/target"
	"github.com/spf13/cobra"
)

var continueCmd = &cobra.Command{
	Use:   "continue",
	Short: "运行到下个断点",
	Annotations: map[string]string{
		cmdGroupAnnotation: cmdGroupCtrlFlow,
	},
	Aliases: []string{"c"},
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		dbp := target.DBPProcess

		// 获取当前停在断点处的线程
		bpStoppedThreads, err := dbp.ThreadStoppedAtBreakpoint()
		if err != nil {
			return fmt.Errorf("check thread breakpoints error: %v", err)
		}

		// 如果没有线程停在断点处，直接继续执行即可
		if len(bpStoppedThreads) == 0 {
			return dbp.Continue()
		}

		// 有线程停在断点处，恢复断点，rewind线程pc，singlestep后恢复断点
		bpCleared := make(map[uintptr]struct{})
		for tid, bpAddr := range bpStoppedThreads {
			fmt.Printf("Thread %d stopped at breakpoint %#x\n", tid, bpAddr)

			// - rewind线程pc
			regs, err := dbp.ReadRegister(tid)
			if err != nil {
				return fmt.Errorf("read register for thread %d: %v", tid, err)
			}
			regs.SetPC(regs.PC() - 1)
			if err = dbp.WriteRegister(tid, regs); err != nil {
				return fmt.Errorf("write register for thread %d: %v", tid, err)
			}

			// - 还原指令数据
			if _, cleared := bpCleared[bpAddr]; !cleared {
				_, err := dbp.ClearBreakpoint(bpAddr)
				if err != nil && err != target.ErrBreakpointNotExisted {
					return fmt.Errorf("clear breakpoint at %#x error: %v", bpAddr, err)
				}
				bpCleared[bpAddr] = struct{}{}
			}

			// - singlestep后，要恢复断点
			_, err = dbp.SingleStep(tid)
			if err != nil {
				return fmt.Errorf("single step for thread %d: %v", tid, err)
			}

			if _, err := dbp.AddBreakpoint(bpAddr); err != nil {
				fmt.Fprintf(os.Stderr, "warning: failed to restore breakpoint at %#x: %v\n", bpAddr, err)
			} else {
				fmt.Printf("restored breakpoint at %#x\n", bpAddr)
			}
		}

		// 然后再恢复所有tracee执行
		if err = dbp.Continue(); err != nil {
			return fmt.Errorf("continue error: %v", err)
		}
		fmt.Println("continue ok")

		return nil
	},
}

func init() {
	debugRootCmd.AddCommand(continueCmd)
}
