package debug

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/hitzhangjie/godbg/target"
	"github.com/spf13/cobra"
	"golang.org/x/arch/x86/x86asm"
)

var disassCmd = &cobra.Command{
	Use:   "disass",
	Short: "反汇编机器指令",
	Annotations: map[string]string{
		cmdGroupAnnotation: cmdGroupSource,
	},
	Aliases: []string{"dis", "disassemble"},
	RunE: func(cmd *cobra.Command, args []string) error {
		var (
			max, _    = cmd.Flags().GetUint("n")
			syntax, _ = cmd.Flags().GetString("syntax")
			err       error
		)

		// 读取PC值
		regs, err := target.DebuggedProcess.ReadRegister()
		if err != nil {
			return err
		}
		fmt.Printf("read PC: %#x\n", regs.PC())

		// 检测PC处是否为断点
		buf := make([]byte, 1)
		n, err := target.DebuggedProcess.ReadMemory(uintptr(regs.PC()), buf)
		if err != nil || n != 1 {
			return fmt.Errorf("peek text error: %v, bytes: %d", err, n)
		}

		// read a breakpoint
		if buf[0] == 0xCC {
			brk, err := target.DebuggedProcess.ClearBreakpoint(uintptr(regs.PC()))
			if err != nil {
				return err
			}
			defer target.DebuggedProcess.AddBreakpoint(brk.Addr)

			// rewind 1 byte
			regs.SetPC(regs.PC() - 1)
			err = target.DebuggedProcess.WriteRegister(regs)
			if err != nil {
				return err
			}
		}

		// 指令数据
		dat := make([]byte, 1024)
		n, err = target.DebuggedProcess.ReadMemory(uintptr(regs.PC()), dat)
		if err != nil || n == 0 {
			return fmt.Errorf("peek text error: %v, bytes: %d", err, n)
		}

		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 8, ' ', 0)

		// 反汇编这里的指令数据
		offset := 0
		count := 0

		for uint(count) < max {
			inst, err := x86asm.Decode(dat[offset:], 64)
			if err != nil {
				return fmt.Errorf("x86asm decode error: %v", err)
			}

			asm, err := instSyntax(inst, syntax)
			if err != nil {
				return fmt.Errorf("x86asm syntax error: %v", err)
			}
			end := offset + inst.Len
			fmt.Fprintf(tw, "%#x:\t% x\t%s\n", regs.PC()+uint64(offset), dat[offset:end], asm)
			offset = end
			count++
		}
		tw.Flush()

		return nil
	},
}

func init() {
	debugRootCmd.AddCommand(disassCmd)

	disassCmd.Flags().UintP("n", "n", 10, "反汇编指令数量")
	disassCmd.Flags().StringP("syntax", "s", "gnu", "反汇编指令语法，支持：go, gnu, intel")
}

// GetExecutable 根据pid获取可执行程序路径
func GetExecutable(pid int) (string, error) {
	exeLink := fmt.Sprintf("/proc/%d/exe", pid)
	exePath, err := os.Readlink(exeLink)
	if err != nil {
		return "", err
	}
	return exePath, nil
}

func instSyntax(inst x86asm.Inst, syntax string) (string, error) {
	asm := ""
	switch syntax {
	case "go":
		asm = x86asm.GoSyntax(inst, uint64(inst.PCRel), nil)
	case "gnu":
		asm = x86asm.GNUSyntax(inst, uint64(inst.PCRel), nil)
	case "intel":
		asm = x86asm.IntelSyntax(inst, uint64(inst.PCRel), nil)
	default:
		return "", fmt.Errorf("invalid asm syntax error")
	}
	return asm, nil
}
