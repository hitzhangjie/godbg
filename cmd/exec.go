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

	"github.com/hitzhangjie/godbg/cmd/debug"
	"github.com/hitzhangjie/godbg/pkg/target"

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
		dbp, err := target.NewDebuggedProcess(args[0], nil, target.EXEC)
		if err != nil {
			return err
		}
		target.DBPProcess = dbp
		return nil
	},
	PostRun: func(cmd *cobra.Command, args []string) {
		// after debugger session finished, we should kill tracee because it's started by debugger
		debug.CurrentSession = debug.NewDebugSession().AtExit(debug.Cleanup)
		debug.CurrentSession.Start()
	},
}

func init() {
	rootCmd.AddCommand(execCmd)
}
