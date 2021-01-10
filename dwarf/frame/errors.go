package frame

import "fmt"

// ErrNoFDEForPC FDE for PC not found error
type ErrNoFDEForPC struct {
	PC uint64
}

func (err *ErrNoFDEForPC) Error() string {
	return fmt.Sprintf("could not find FDE for PC %#v", err.PC)
}
