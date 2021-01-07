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
	"syscall"

	"github.com/hitzhangjie/godbg/cmd/debug"
	"github.com/hitzhangjie/godbg/target"

	"github.com/spf13/cobra"
)

// execCmd represents the exec command
var execCmd = &cobra.Command{
	Use:   "exec <prog>",
	Short: "调试可执行程序",
	Long:  `调试可执行程序`,
	RunE: func(cmd *cobra.Command, args []string) error {

		if len(args) != 1 {
			return errors.New("参数错误")
		}

		// start tracee and wait tracee stopped
		dbp, err := target.NewTargetProcess(args[0])
		if err != nil {
			return err
		}
		target.DebuggedProcess = dbp
		return nil
	},
	PostRunE: func(cmd *cobra.Command, args []string) error {
		debug.NewDebugShell().Run()
		// after debugger session finished, we should kill tracee because it's started by debugger
		return syscall.Kill(target.DebuggedProcess.Process.Pid, 0)
	},
}

func init() {
	rootCmd.AddCommand(execCmd)
}
