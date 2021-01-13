/*
Copyright © 2020 NAME HERE <EMAIL ADDRESS>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"errors"
	"fmt"
	"os"
	"strconv"

	"github.com/hitzhangjie/godbg/cmd/debug"
	"github.com/hitzhangjie/godbg/target"

	"github.com/spf13/cobra"
)

// attachCmd represents the attach command
var attachCmd = &cobra.Command{
	Use:   "attach <traceePID>",
	Short: "调试运行中进程",
	Long:  `调试运行中进程`,
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		if len(args) != 1 {
			return errors.New("参数错误")
		}

		pid, err := strconv.ParseInt(args[0], 10, 64)
		if err != nil {
			fmt.Printf("%s invalid traceePID\n", os.Args[2])
			os.Exit(1)
		}

		dbp, err := target.AttachTargetProcess(int(pid))
		if err != nil {
			return err
		}
		target.DebuggedProcess = dbp
		return nil
	},
	PostRun: func(cmd *cobra.Command, args []string) {
		// after debugger session finished, we should kill tracee because it's started by debugger
		debug.CurrentSession = debug.NewDebugSession().AtExit(debug.Cleanup)
		debug.CurrentSession.Start()
	},
}

func init() {
	rootCmd.AddCommand(attachCmd)
}
