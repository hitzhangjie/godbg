package symbol

import (
	"debug/dwarf"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/hitzhangjie/godbg/pkg/dwarf/frame"
	"github.com/hitzhangjie/godbg/pkg/dwarf/godwarf"
	"github.com/hitzhangjie/godbg/pkg/dwarf/reader"
	"golang.org/x/arch/x86/x86asm"
)

// BinaryInfo binary info
type BinaryInfo struct {
	Sources      map[string]map[int][]*dwarf.LineEntry // key=filename, val=map[lineno]lineEntries
	Functions    []*Function
	CompileUnits []*CompileUnit
	FdeEntries   frame.FrameDescriptionEntries

	// only used for parsing purpose
	curEntry            *dwarf.Entry
	curCompileUnitEntry *dwarf.Entry
	curSubprogramEntry  *dwarf.Entry

	curCompileUnit *CompileUnit
	curFunction    *Function
}

// Analyze Analyze executable `execFile` and return the binary info
func Analyze(execFile string) (*BinaryInfo, error) {

	file, err := elf.Open(execFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// check info and frame section
	_, err = godwarf.GetDebugSection(file, "info")
	if err != nil {
		return nil, err
	}
	_, err = godwarf.GetDebugSection(file, "line")
	if err != nil {
		return nil, err
	}

	bi := &BinaryInfo{
		Sources: make(map[string]map[int][]*dwarf.LineEntry),
	}

	// parse dwarf
	dwarfData, err := file.DWARF()
	if err != nil {
		return nil, err
	}

	// parse .(z)debug_line and .(z)debug_info
	if err = bi.ParseLineAndInfo(dwarfData); err != nil {
		return nil, err
	}

	// parse .(z)debug_frame
	if err = bi.ParseFrame(file); err != nil {
		return nil, err
	}

	return bi, nil
}

// ParseLineAndInfo parseFrom .(z)debug_line and .(z)debug_info sections
//
// unit entries: see DWARF v4 chapter 3.3.1 normal and partial compilation unit entries
func (bi *BinaryInfo) ParseLineAndInfo(dwarfData *dwarf.Data) error {

	reader := reader.New(dwarfData)
	for {
		entry, err := reader.Next()
		if err != nil {
			return err
		}
		if entry == nil { // reaches the end
			break
		}
		bi.curEntry = entry

		// parse compile unit and line table
		if entry.Tag == dwarf.TagCompileUnit {
			cu := &CompileUnit{entry: entry}
			bi.curCompileUnit = cu
			bi.curCompileUnitEntry = entry

			rd, err := dwarfData.LineReader(entry)
			if err != nil {
				return err
			}

			filename, lineMappings, err := cu.parseLineSection(rd)
			if err != nil {
				return err
			}

			orig, ok := bi.Sources[filename]
			if !ok || orig == nil {
				bi.Sources[filename] = lineMappings
				continue
			}

			for ln, entries := range lineMappings {
				v, ok := orig[ln]
				if !ok {
					orig[ln] = entries
					continue
				}
				v = append(v, entries...)
				orig[ln] = v
			}
		}

		// parse subprogram
		if entry.Tag == dwarf.TagSubprogram {
			fn := &Function{}
			bi.curFunction = fn
			bi.Functions = append(bi.Functions, fn)
			bi.curCompileUnit.functions = append(bi.curCompileUnit.functions, fn)
			bi.curSubprogramEntry = entry

			err = fn.parseFrom(entry)
			if err != nil {
				return err
			}
		}

		// parse variables defined in subprogram
		if entry.Tag == dwarf.TagVariable {
			bi.curFunction.variables = append(bi.curFunction.variables, entry)
		}
	}

	return nil
}

// ParseFrame parse .(z)debug_frame section to build the Call Frame Information
//
// see DWARFv4 6.4 Call Frame Information.
func (bi *BinaryInfo) ParseFrame(elffile *elf.File) error {
	frameData, err := godwarf.GetDebugSection(elffile, "frame")
	if err != nil {
		return err
	}

	ptrSize := int(unsafe.Sizeof(uintptr(0)))
	frameEntries := frame.Parse(frameData, binary.LittleEndian, 0, ptrSize)

	if len(frameEntries) == 0 {
		return errors.New("no frame entries found")
	}
	bi.FdeEntries = frameEntries

	return nil
}

// PCToFunction returns the function whose range covers PC
//
// note: not considered inline function
func (bi *BinaryInfo) PCToFunction(pc uint64) (*Function, error) {
	for _, f := range bi.Functions {
		if f.lowpc <= pc && pc < f.highpc {
			return f, nil
		}
	}
	return nil, errors.New("not found")
}

// PCToFDE returns the frame whose range covers PC
func (bi *BinaryInfo) PCToFDE(pc uint64) (*frame.FrameDescriptionEntry, error) {
	return bi.FdeEntries.FDEForPC(pc)
}

// parseLoc parse location `loc` to file:lineno
func parseLoc(loc string) (string, int, error) {
	sps := strings.Split(loc, ":")
	if len(sps) != 2 {
		return "", 0, errors.New("wrong loc should be like filename:lineno")
	}
	filename, linenostr := sps[0], sps[1]
	lineno, err := strconv.Atoi(linenostr)
	if err != nil {
		return "", 0, errors.New("wrong loc should be like filename:lineno")
	}
	return filename, lineno, nil
}

// LocToPC convert location `loc` to PC
func (bi *BinaryInfo) LocToPC(loc string) (uint64, error) {
	filename, lineno, err := parseLoc(loc)
	if err != nil {
		return 0, err
	}
	return bi.FileLineToPC(filename, lineno)
}

// FileLineToPC convert location `filename:lineno` to PC
func (bi *BinaryInfo) FileLineToPC(filename string, lineno int) (uint64, error) {
	if bi.Sources[filename] == nil ||
		bi.Sources[filename][lineno] == nil ||
		len(bi.Sources[filename][lineno]) == 0 {
		return 0, errors.New("not found")
	}
	return bi.Sources[filename][lineno][0].Address, nil
}

// FileLineToPCForBreakpoint convert location `filename:lineno` to PC, used for breakpoint address
func (bi *BinaryInfo) FileLineToPCForBreakpoint(filename string, lineno int) (uint64, error) {
	if bi.Sources[filename] == nil ||
		bi.Sources[filename][lineno] == nil ||
		len(bi.Sources[filename][lineno]) == 0 {
		return 0, errors.New("not found")
	}
	lineEntries := bi.Sources[filename][lineno]
	// skip prologue
	for _, v := range lineEntries {
		if v.PrologueEnd {
			return v.Address, nil
		}
	}
	// TODO why?
	addr := uint64(0)
	for i, v := range lineEntries {
		if i == 0 {
			addr = v.Address
		} else {
			if addr > v.Address {
				addr = v.Address
			}
		}
	}
	if addr == 0 {
		return 0, errors.New("not found")
	}
	return addr, nil
}

func (bi *BinaryInfo) PCToFileLine(pc uint64) (string, int, error) {
	if bi.Sources == nil {
		return "", 0, errors.New("no sources file")
	}

	type Rs struct {
		pc        uint64
		existedPc bool
		filename  string
		lineno    int
	}

	rangeMin := &Rs{}
	rangeMax := &Rs{}

	for filename, filenameMp := range bi.Sources {
		for lineno, lineEntryArray := range filenameMp {
			for _, lineEntry := range lineEntryArray {
				if lineEntry.Address == pc {
					return filename, lineno, nil
				}
				if lineEntry.Address <= pc && (!rangeMin.existedPc || lineEntry.Address > rangeMin.pc) {
					rangeMin.pc = lineEntry.Address
					rangeMin.existedPc = true
					rangeMin.filename = filename
					rangeMin.lineno = lineno
				}
				if pc < lineEntry.Address && (!rangeMax.existedPc || lineEntry.Address < rangeMax.pc) {
					rangeMax.pc = lineEntry.Address
					rangeMax.existedPc = true
					rangeMax.filename = filename
					rangeMax.lineno = lineno
				}
			}
		}
	}

	return rangeMin.filename, rangeMin.lineno, nil
}

// Deprecated: use bi.Target.ReadMemory or bi.Target.Disassemble instead
func (bi *BinaryInfo) getSingleMemInst(pid int, pc uint64) (x86asm.Inst, error) {
	var (
		mem  []byte
		err  error
		inst x86asm.Inst
	)

	mem = make([]byte, 100)
	if _, err = syscall.PtracePeekData(pid, uintptr(pc), mem); err != nil {
		return x86asm.Inst{}, err
	}
	if inst, err = x86asm.Decode(mem, 64); err != nil {
		return x86asm.Inst{}, err
	}
	return inst, nil
}

func (bi *BinaryInfo) Dump() {

	// debug source log
	for file, mp := range bi.Sources {
		for line, lineEntryArray := range mp {
			for _, lineEntry := range lineEntryArray {
				fmt.Printf("bi.sources file: %s, line: %d, addr: %#x\n", file, line, lineEntry.Address)
			}
		}
	}

	// debug compile unit
	for _, cu := range bi.CompileUnits {
		fmt.Printf("compile unit: %s\n", cu.name())
	}

	// debug frame log
	for i, v := range bi.FdeEntries {
		if v.CIE != nil {
			fmt.Printf("bi.frames index: %d, cie: %v\n", i, v.CIE)
			continue
		}
		fmt.Printf("bi.frames index: %d, fde: [%#x, %#x]\n", i, v.Begin(), v.End())
	}

	// dump functions
	for _, fn := range bi.Functions {
		for _, field := range fn.entry.Field {
			fmt.Println("|================= START ===========================|")
			fmt.Printf("TagSubprogram Attr: %s, Val: %v, Class: %v\n",
				field.Attr.String(),
				fmt.Sprintf("%v", field.Val),
				fmt.Sprintf("%s", field.Class))
			fmt.Println("|================== END ============================|")
		}
	}

	// debug variables
	for _, fn := range bi.Functions {
		for _, entry := range fn.variables {
			fields := entry.Field
			fmt.Println("|================= START ===========================|")
			for _, field := range fields {
				fmt.Printf("%s Attr: %s, Val: %v, Class: %s\n",
					entry.Tag.GoString(), field.Attr.String(), field.Val, field.Class)
			}
			fmt.Println("|================== END ============================|")
		}
	}
}
