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
	entry     *dwarf.Entry
	bi        *BinaryInfo
}

// parseLineSection parse .(z)debug_line, return file, line entries
//
// note: one compile unit may contains more than one source files.
func (c *CompileUnit) parseLineSection(lineReader *dwarf.LineReader) error {

	entry := dwarf.LineEntry{}

	for {
		// scan next entry
		err := lineReader.Next(&entry)
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if entry.File == nil {
			continue
		}

		// append line entries
		file := entry.File.Name
		entries, ok := c.bi.Sources[file]
		if !ok {
			entries = make(map[int][]*dwarf.LineEntry)
			c.bi.Sources[file] = entries
		}

		dup := entry
		entries[entry.Line] = append(entries[entry.Line], &dup)
	}

	return nil
}

func (c *CompileUnit) name() string {
	return c.entry.Val(dwarf.AttrName).(string)
}
