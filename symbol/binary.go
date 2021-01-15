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

	"github.com/hitzhangjie/godbg/dwarf/frame"
	"github.com/hitzhangjie/godbg/dwarf/godwarf"
	"github.com/hitzhangjie/godbg/dwarf/reader"
	"golang.org/x/arch/x86/x86asm"
)

// BinaryInfo binary info
type BinaryInfo struct {
	Sources      map[string]map[int][]*dwarf.LineEntry // key=filename, val=map[lineno]lineEntries
	Functions    []*Function
	CompileUnits []*CompileUnit
	FdeEntries   frame.FrameDescriptionEntries

	// used for parsing purpose
	curEntry            *dwarf.Entry
	curCompileUnitEntry *dwarf.Entry
	curSubprogramEntry  *dwarf.Entry

	curCompileUnit *CompileUnit
	curFunction    *Function
}

// Analyze Analyze executable `execfile` and return the binary info
func Analyze(fname string) (*BinaryInfo, error) {

	file, err := elf.Open(fname)
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

	// parseFunction
	dwarfData, err := file.DWARF()
	if err != nil {
		return nil, err
	}

	if err = bi.ParseLineAndInfoSection(dwarfData); err != nil {
		return nil, err
	}
	if err = bi.ParseFrameSection(file); err != nil {
		return nil, err
	}

	// debug source log
	for file, mp := range bi.Sources {
		for line, lineEntryArray := range mp {
			for _, lineEntry := range lineEntryArray {
				fmt.Printf("bi.sources file: %s, line: %s, addr: %#x\n", file, line, lineEntry.Address)
			}
		}
	}

	// debug frame log
	for i, v := range bi.FdeEntries {
		if v.CIE != nil {
			fmt.Printf("bi.frames index: %d, cie: %vs\n", i, v.CIE)
			continue
		}
		fmt.Printf("bi.frames index: %d, fde: [%#x, %#x]\n", i, v.Begin(), v.End())
	}

	return bi, nil
}

// ParseLineAndInfoSection parseFunction .(z)debug_line and .(z)debug_info sections
//
// unit entries: see DWARF v4 chapter 3.3.1 normal and partial compilation unit entries
func (bi *BinaryInfo) ParseLineAndInfoSection(dwarfData *dwarf.Data) error {

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

			lineMappings, err := cu.parseLineSection(rd)
			if err != nil {
				return err
			}

			if bi.Sources[cu.Name()] == nil {
				bi.Sources[cu.Name()] = lineMappings
			} else {
				panic("single file is split into multiple compilation units????")
			}
		}

		// parse subprogram
		if entry.Tag == dwarf.TagSubprogram {
			fn := &Function{}
			bi.curFunction = fn
			bi.Functions = append(bi.Functions, fn)
			bi.curCompileUnit.functions = append(bi.curCompileUnit.functions, fn)
			bi.curSubprogramEntry = entry

			err = fn.parseFunction(entry)
			if err != nil {
				return err
			}
		}

		// parse variables defined in subprogram
		if entry.Tag == dwarf.TagVariable {
			bi.curFunction.variables = append(bi.curFunction.variables, entry)
			fmt.Println("|================= START ===========================|")
			fields := entry.Field
			for _, field := range fields {
				fmt.Printf("%s Attr: %s, Val: %v, Class: %s\n", entry.Tag.GoString(), field.Attr.String(), field.Class)
			}
			fmt.Println("|================== END ============================|")
		}
	}

	return nil
}

// not considered inline function
func (bi *BinaryInfo) findFunctionIncludePc(pc uint64) (*Function, error) {
	for _, f := range bi.Functions {
		if f.lowpc <= pc && pc < f.highpc {
			return f, nil
		}
	}
	return nil, errors.New("not found")
}

func (bi *BinaryInfo) ParseFrameSection(elffile *elf.File) error {
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

func (bi *BinaryInfo) findFrameInformation(pc uint64) (*frame.FrameDescriptionEntry, error) {
	return bi.FdeEntries.FDEForPC(pc)
}

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

func (bi *BinaryInfo) locToPc(loc string) (uint64, error) {
	filename, lineno, err := parseLoc(loc)
	if err != nil {
		return 0, err
	}
	return bi.fileLineToPc(filename, lineno)
}

func (bi *BinaryInfo) fileLineToPc(filename string, lineno int) (uint64, error) {
	if bi.Sources[filename] == nil ||
		bi.Sources[filename][lineno] == nil ||
		len(bi.Sources[filename][lineno]) == 0 {
		return 0, errors.New("not found")
	}
	return bi.Sources[filename][lineno][0].Address, nil
}

func (bi *BinaryInfo) fileLineToPcForBreakPoint(filename string, lineno int) (uint64, error) {
	if bi.Sources[filename] == nil ||
		bi.Sources[filename][lineno] == nil ||
		len(bi.Sources[filename][lineno]) == 0 {
		return 0, errors.New("not found")
	}
	lineEntryArray := bi.Sources[filename][lineno]
	for _, v := range lineEntryArray {
		if v.PrologueEnd {
			return v.Address, nil
		}
	}
	addr := uint64(0)
	for i, v := range lineEntryArray {
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

func (bi *BinaryInfo) getCurFileLineByPc(pc uint64) (string, int, error) {
	return bi.pcTofileLine(pc)
}

func (bi *BinaryInfo) pcTofileLine(pc uint64) (string, int, error) {
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
