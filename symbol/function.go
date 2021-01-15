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

	variables []*dwarf.Entry
	cu        *CompileUnit
}

func (f *Function) parseFunction(curEntry *dwarf.Entry) error {

	fields := curEntry.Field
	fmt.Println("|================= START ===========================|")
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
			fmt.Printf("analyze:TagSubprogram unknow attr field: %s", field)
		}
		// for debug log
		fmt.Printf("TagSubprogram Attr: %s, Val: %v, Class: %v\n",
			field.Attr.String(),
			fmt.Sprintf("%v", field.Val),
			fmt.Sprintf("%s", field.Class))
	}
	fmt.Println("|================== END ============================|")

	return nil
}
