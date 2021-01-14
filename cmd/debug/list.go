package debug

import (
	"debug/gosym"
	"errors"
	"fmt"
	"io/ioutil"
	"strconv"
	"strings"

	"github.com/hitzhangjie/godbg/target"
	"github.com/spf13/cobra"
	cobraprompt "github.com/stromland/cobra-prompt"
)

var listCmd = &cobra.Command{
	Use:     "list [linespec]",
	Short:   "查看源码信息",
	Aliases: []string{"l"},
	Annotations: map[string]string{
		cmdGroupAnnotation:              cmdGroupSource,
		cobraprompt.CALLBACK_ANNOTATION: suggestionListSourceFiles,
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		var (
			file   string
			lineno int
			fn     *gosym.Func
			err    error
		)

		// parse location
		if len(args) != 0 {

			file, lineno, err = parseLocation(args[0])
			if err != nil {
				return err
			}

		} else {

			regs, err := target.DebuggedProcess.ReadRegister()
			if err != nil {
				return err
			}
			pc := regs.PC()

			_, ok := target.DebuggedProcess.Breakpoints[uintptr(pc)]
			if ok {
				pc--
			}

			file, lineno, fn = target.DebuggedProcess.Table.PCToLine(pc)
			if fn == nil {
				return errors.New("invalid locspec")
			}
		}

		// print lines
		return listFileLines(file, lineno, 5)
	},
}

func listFileLines(file string, lineno, rng int) error {

	lines, offset, err := listFile(file, lineno, rng)
	if err != nil {
		return fmt.Errorf("list file err: %v", err)
	}

	idx := offset
	for _, ln := range lines {
		if idx != lineno {
			fmt.Printf("%-4s\t%d\t%s\n", "", idx, ln)
		} else {
			fmt.Printf("%-4s\t%d\t%s\n", "=>", idx, ln)
		}
		idx++
	}

	return nil
}

func init() {
	debugRootCmd.AddCommand(listCmd)
}

// Location location in source code, see LocSpec below
type Location string

type LocSpec string

const (
	FileLineNo  = iota << 1 // like main.go:100
	FileFunc                // like main.go:main
	PackageFunc             // like main.main
)

// must be form file:lineno, like main.go:100
func parseLocation(s string) (file string, lineno int, err error) {
	vals := strings.Split(s, ":")
	if len(vals) != 2 {
		err = fmt.Errorf("invalid location: %s, must be file:lineno", s)
		return
	}

	file = vals[0]
	v, err := strconv.ParseInt(vals[1], 10, 64)
	if err != nil {
		err = fmt.Errorf("invalid location: %s, must be file:lineno", s)
		return
	}
	lineno = int(v)
	return
}

func parseLocationByPC() (file string, lineno int, err error) {
	regs, err := target.DebuggedProcess.ReadRegister()
	if err != nil {
		return
	}

	pc := regs.PC()
	_, ok := target.DebuggedProcess.Breakpoints[uintptr(pc)]
	if ok {
		pc--
	}

	file, lineno, fn := target.DebuggedProcess.Table.PCToLine(pc)
	if fn == nil {
		err = errors.New("invalid locspec")
		return
	}
	return
}

func listFile(file string, lineno, rng int) (lines []string, offset int, err error) {
	dat, err := ioutil.ReadFile(file)
	if err != nil {
		err = fmt.Errorf("read file err: %v", err)
		return
	}

	raw := strings.Split(string(dat), "\n")
	count := len(raw)

	begin := lineno - rng
	if begin < 0 {
		begin = 0
	}
	if begin > count {
		return
	}

	end := lineno + rng
	if end > count {
		end = count
	}

	return raw[begin:end], begin, nil
}
