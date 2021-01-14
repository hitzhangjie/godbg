package debug

import (
	"bytes"
	"debug/elf"
	"debug/gosym"
	"encoding/binary"
	"fmt"

	"github.com/hitzhangjie/godbg/target"
	"github.com/spf13/cobra"
)

var backtraceCmd = &cobra.Command{
	Use:     "bt",
	Short:   "打印调用栈信息",
	Aliases: []string{"backtrace"},
	Annotations: map[string]string{
		cmdGroupAnnotation: cmdGroupInfo,
	},
	RunE: func(cmd *cobra.Command, args []string) error {

		pid := target.DebuggedProcess.Process.Pid

		// 获取当前寄存器状态
		regs, err := target.DebuggedProcess.ReadRegister()
		if err != nil {
			return err
		}

		// open elf file
		file, err := elf.Open(fmt.Sprintf("/proc/%d/exe", pid))
		if err != nil {
			return err
		}

		// read elf sections
		pcln, err := file.Section(".gopclntab").Data()
		if err != nil {
			return err
		}

		sym, err := file.Section(".gosymtab").Data()
		if err != nil {
			return err
		}

		lntab := gosym.NewLineTable(pcln, regs.PC())
		tab, err := gosym.NewTable(sym, lntab)
		if err != nil {
			return err
		}

		// print stack trace
		bp := regs.Rbp
		pc := regs.PC()
		idx := 0
		ret := uint64(0)

		f, n, fn := tab.PCToLine(pc - 1)
		fmt.Printf("#%d %s %s:%d\n", idx, fn.Name, f, n)

		for {
			idx++
			if bp == 0 {
				break
			}

			//addr := rbp
			buf := make([]byte, 16)

			n, err := target.DebuggedProcess.ReadMemory(uintptr(bp), buf)
			if err != nil || n != 16 {
				return fmt.Errorf("read mermory err: %v, bytes: %d", err, n)
			}

			// bp of previous caller stackframe
			reader := bytes.NewBuffer(buf)
			err = binary.Read(reader, binary.LittleEndian, &bp)
			if err != nil {
				return err
			}

			// ret address
			err = binary.Read(reader, binary.LittleEndian, &ret)
			if err != nil {
				return err
			}

			// TODO：暂时不考虑内联、尾递归优化（go编译器暂时不支持尾递归优化）的话，ret基本上对应着调用方函数的栈帧，
			// 但是为了让源代码位置更精准，这里的减去对ret减1
			f, n, fn := tab.PCToLine(ret - 1)
			fmt.Printf("#%d %s %s:%d\n", idx, fn.Name, f, n)
		}
		return nil
	},
}

func init() {
	debugRootCmd.AddCommand(backtraceCmd)
}
