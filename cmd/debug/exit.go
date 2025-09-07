package debug

import (
	"fmt"
	"os"
	"syscall"

	"github.com/hitzhangjie/godbg/pkg/target"
	"github.com/spf13/cobra"
)

var exitCmd = &cobra.Command{
	Use:   "exit",
	Short: "结束调试会话",
	Annotations: map[string]string{
		cmdGroupAnnotation: cmdGroupOthers,
	},
	Run: func(cmd *cobra.Command, args []string) {
		CurrentSession.Stop()
	},
}

func init() {
	debugRootCmd.AddCommand(exitCmd)
}

// Cleanup 清理调试会话
func Cleanup() {
	var (
		dbp = target.DBPProcess
		err error
	)
	// 根据被调试进程创建的方式，debug、exec or attach，来决定如何做善后处理
	// - debug: kill traced process, delete generated binary
	// - exec: kill traced process
	// - attach: detach traced process
	if err = dbp.Detach(); err != nil {
		fmt.Fprintf(os.Stderr, "detach tracee: %d, err: %v\n", dbp.Process.Pid, err)
		return
	}

	switch dbp.Kind {
	case target.DEBUG:
		fmt.Fprintf(os.Stdout, "tracee is is built and run by tracer, remove binary and kill it: %d\n", dbp.Kind)

		if err = os.RemoveAll(dbp.Command); err != nil {
			fmt.Fprintf(os.Stderr, "remove built binary %s, err: %v\n", dbp.Command, err)
			return
		}
		if err = syscall.Kill(dbp.Process.Pid, syscall.SIGKILL); err != nil {
			fmt.Fprintf(os.Stderr, "kill tracee: %d, err: %v\n", dbp.Process.Pid, err)
			return
		}
		fallthrough
	case target.EXEC:
		fmt.Fprintf(os.Stdout, "tracee is is run by tracer, kill it: %d\n", dbp.Kind)
		if err = syscall.Kill(dbp.Process.Pid, syscall.SIGKILL); err != nil {
			fmt.Fprintf(os.Stderr, "kill tracee: %d, err: %v\n", dbp.Process.Pid, err)
			return
		}
	default:
		fmt.Fprintf(os.Stdout, "tracee is an attached process, leave it running: %d\n", dbp.Kind)
	}
}
