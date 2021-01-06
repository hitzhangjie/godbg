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
	"syscall"

	"github.com/hitzhangjie/godbg/cmd/debug"
	"github.com/spf13/cobra"
)

const (
	buildExecName = "./__debug_bin__"
)

// debugCmd represents the debug command
var debugCmd = &cobra.Command{
	Use:   "debug [directory|file]",
	Short: "build and debug go program",
	Long:  `build and debug go program.`,
	RunE: func(cmd *cobra.Command, args []string) error {

		// build and run tracee
		target := []string{"."}
		if len(args) != 0 {
			target = args
		}

		cmdArgs := []string{"build", "-gcflags=all=-N -l", "-o", buildExecName}
		cmdArgs = append(cmdArgs, target...)
		buildCmd := exec.Command("go", cmdArgs...)

		if buf, err := buildCmd.CombinedOutput(); err != nil {
			fmt.Fprintf(os.Stderr, "build error: %v\n", err)
			fmt.Fprintf(os.Stderr, "\terrmsg: %s\n", string(buf))
			return err
		}
		fmt.Printf("build ok\n")

		return executeCommand(buildExecName)
	},
	PostRunE: func(cmd *cobra.Command, args []string) error {
		debug.NewDebugShell().Run()
		defer os.RemoveAll(buildExecName)
		// after debugger session finished, we should kill tracee because it's started by debugger
		return syscall.Kill(debug.TraceePID, 0)
	},
}

func init() {
	rootCmd.AddCommand(debugCmd)
}
