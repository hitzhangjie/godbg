package target

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"regexp"
	"strings"
)

// readProcComm read /proc/pid/comm or /proc/pid/stat to load the command line of process.
func readProcComm(pid int) (string, error) {
	comm, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err == nil {
		// removes newline character
		comm = bytes.TrimSuffix(comm, []byte("\n"))
	}

	if comm == nil || len(comm) <= 0 {
		stat, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if err != nil {
			return "", fmt.Errorf("could not read proc stat: %v", err)
		}
		expr := fmt.Sprintf("%d\\s*\\((.*)\\)", pid)
		rexp, err := regexp.Compile(expr)
		if err != nil {
			return "", fmt.Errorf("regexp compile error: %v", err)
		}
		match := rexp.FindSubmatch(stat)
		if match == nil {
			return "", fmt.Errorf("no match found using regexp '%s' in /proc/%d/stat", expr, pid)
		}
		comm = match[1]
	}

	cmdStr := strings.ReplaceAll(string(comm), "%", "%%")
	return cmdStr, nil
}

// readProcCommArgs read /proc/pid/cmdline to load the command arguments of process
func readProcCommArgs(pid int) ([]string, error) {
	dat, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return nil, err
	}
	args := strings.Split(string(dat), string([]byte{0}))[1:]
	return args, nil
}
