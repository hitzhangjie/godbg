/*
Copyright © 2020 hit.zhangjie@gmail.com

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
package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/hitzhangjie/godbg/cmd"
	"github.com/hitzhangjie/godbg/pkg/target"
)

func main() {
	go processSignals()
	cmd.Execute()
}

func processSignals() {
	ch := make(chan os.Signal, 16)
	signal.Notify(ch, syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGURG)

	for sig := range ch {

		switch sig {
		case syscall.SIGURG:
			// 非协作式抢占信号，忽略这个信号
			break
		case syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT:
			os.RemoveAll(cmd.BuildExecName)
			syscall.Kill(target.DBPProcess.Process.Pid, 0)
			os.Exit(0)
		}
	}
}
