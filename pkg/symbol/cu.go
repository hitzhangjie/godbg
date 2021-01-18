package symbol

import (
	"debug/dwarf"
	"io"
)

// CompileUnit compilation unit
//
// see DWARFv4 3.1.1 normal and partial compilation unit entries
type CompileUnit struct {
	functions []*Function

	entry *dwarf.Entry
}

// parseLineSection parse .(z)debug_line, return file, line entries
func (c *CompileUnit) parseLineSection(lineReader *dwarf.LineReader) (string, map[int][]*dwarf.LineEntry, error) {

	file := ""
	lineMappings := map[int][]*dwarf.LineEntry{}

	for {
		lnEntry := dwarf.LineEntry{}
		err := lineReader.Next(&lnEntry)

		if err == io.EOF {
			break
		}
		if err != nil {
			return "", nil, err
		}

		if len(file) == 0 {
			file = lnEntry.File.Name
		}

		//fmt.Printf("compile unit: %s, line entry: %v\n", c.name(), lnEntry)

		if lnEntry.File == nil {
			continue
		}

		dup := lnEntry
		lineMappings[lnEntry.Line] = append(lineMappings[lnEntry.Line], &dup)
	}

	return file, lineMappings, nil
}

func (c *CompileUnit) name() string {
	return c.entry.Val(dwarf.AttrName).(string)
}
