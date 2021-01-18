package target

// Kind 调试发起类型
type Kind int

const (
	DEBUG Kind = iota
	EXEC
	ATTACH
)

