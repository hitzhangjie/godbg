package symbol

import (
	"debug/dwarf"
	"fmt"
)

// Function function
//
// see DWARFv4 3.3 subroutine and entry point entries
type Function struct {
	name      string
	lowpc     uint64
	highpc    uint64
	frameBase []byte
	declFile  int64
	external  bool

	entry     *dwarf.Entry
	variables []*dwarf.Entry
	cu        *CompileUnit
}

func (f *Function) Name() string {
	return f.name
}

func (f *Function) Variables() []*dwarf.Entry {
	return f.variables
}

func (f *Function) parseFrom(curEntry *dwarf.Entry) error {

	fields := curEntry.Field

	for _, field := range fields {
		switch field.Attr {
		case dwarf.AttrName:
			if val, ok := field.Val.(string); ok {
				f.name = val
			}
		case dwarf.AttrLowpc:
			if val, ok := field.Val.(uint64); ok {
				f.lowpc = val
			}
		case dwarf.AttrHighpc:
			if val, ok := field.Val.(uint64); ok {
				f.highpc = val
			}
		case dwarf.AttrFrameBase:
			if val, ok := field.Val.([]byte); ok {
				f.frameBase = val
			}
		case dwarf.AttrDeclFile:
			if val, ok := field.Val.(int64); ok {
				f.declFile = val
			}
		case dwarf.AttrExternal:
			if val, ok := field.Val.(bool); ok {
				f.external = val
			}
		default:
			fmt.Printf("analyze:TagSubprogram unknown attr field: %s", field.Attr.String())
		}
	}

	f.entry = curEntry
	return nil
}
