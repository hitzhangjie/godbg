package symbol

import (
	"debug/dwarf"
	"fmt"
	"io"
)

// CompileUnit compilation unit
//
// see DWARFv4 3.1.1 normal and partial compilation unit entries
type CompileUnit struct {
	functions []*Function

	entry *dwarf.Entry
}

func (c *CompileUnit) parseLineSection(lineReader *dwarf.LineReader) (map[int][]*dwarf.LineEntry, error) {

	lineMappings := map[int][]*dwarf.LineEntry{}

	for {
		lnEntry := dwarf.LineEntry{}
		err := lineReader.Next(&lnEntry)

		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		fmt.Printf("compile unit: %s, line entry: %v\n", c.name(), lnEntry)

		if lnEntry.File == nil {
			continue
		}

		dup := lnEntry
		lineMappings[lnEntry.Line] = append(lineMappings[lnEntry.Line], &dup)
	}

	return lineMappings, nil
}

func (c *CompileUnit) name() string {
	return c.entry.Val(dwarf.AttrName).(string)
}
