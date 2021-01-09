package debug

import (
	"fmt"
	"os"
	"syscall"

	"github.com/hitzhangjie/godbg/target"
	"github.com/spf13/cobra"
)

var exitCmd = &cobra.Command{
	Use:   "exit",
	Short: "结束调试会话",
	Annotations: map[string]string{
		cmdGroupAnnotation: cmdGroupOthers,
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		// 根据被调试进程创建的方式，debug、exec or attach，来决定如何做善后处理
		// - debug: kill traced process, delete generated binary
		// - exec: kill traced process
		// - attach: detach traced process
		dbp := target.DebuggedProcess
		err := dbp.Detach()
		if err != nil {
			return err
		}

		switch dbp.Kind {
		case target.DEBUG:
			err = os.RemoveAll(dbp.Command)
			if err != nil {
				return err
			}
			fallthrough
		case target.EXEC:
			err = syscall.Kill(dbp.Process.Pid, 0)
			if err != nil {
				return err
			}
		default:
			fmt.Println("what the fuck")
		}
		os.Exit(0)
		return nil
	},
}

func init() {
	debugRootCmd.AddCommand(exitCmd)
}
