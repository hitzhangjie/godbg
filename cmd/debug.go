/*
Copyright © 2021 NAME HERE <EMAIL ADDRESS>

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
	"fmt"
	"os"
	"os/exec"

	"github.com/hitzhangjie/godbg/cmd/debug"
	"github.com/hitzhangjie/godbg/pkg/target"
	"github.com/spf13/cobra"
)

const (
	BuildExecName = "./__debug_bin__"
)

// debugCmd represents the debug command
var debugCmd = &cobra.Command{
	Use:   "debug [directory|file]",
	Short: "build and debug go program",
	Long:  `build and debug go program.`,
	RunE: func(cmd *cobra.Command, args []string) error {

		// build and run tracee
		cmdName := []string{"."}
		if len(args) != 0 {
			cmdName = args
		}

		cmdArgs := []string{"build", "-gcflags=all=-N -l", "-ldflags=-compressdwarf=false", "-o", BuildExecName}
		cmdArgs = append(cmdArgs, cmdName...)
		buildCmd := exec.Command("go", cmdArgs...)

		if buf, err := buildCmd.CombinedOutput(); err != nil {
			fmt.Fprintf(os.Stderr, "build error: %v\n", err)
			fmt.Fprintf(os.Stderr, "\terrmsg: %s\n", string(buf))
			return err
		}

		// start tracee and wait tracee stopped
		// TODO allow passing arguments after `--`
		dbp, err := target.NewDebuggedProcess(BuildExecName, nil, target.DEBUG)
		if err != nil {
			return err
		}
		target.DBPProcess = dbp

		// 打印解析的符号信息，供调试用
		verbose, _ := cmd.Flags().GetBool("verbose")
		if verbose {
			dbp.BInfo.Dump()
		}

		return nil
	},
	PostRun: func(cmd *cobra.Command, args []string) {
		// after debugger session finished, we should kill tracee because it's started by debugger
		debug.CurrentSession = debug.NewDebugSession().AtExit(debug.Cleanup)
		debug.CurrentSession.Start()
		os.RemoveAll(BuildExecName)
	},
}

func init() {
	rootCmd.AddCommand(debugCmd)
}
