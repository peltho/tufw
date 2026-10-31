package utils

import (
	"bytes"
	"os/exec"
	"strconv"
	"strings"
)

func Shellout(command string) (string, string, error) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd := exec.Command("bash", "-c", command)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

func ValidatePort(text string, ch rune) bool {
	_, err := strconv.Atoi(text)
	return err == nil
}

func ParseInterfaceIndex(input string, interfaces []string) int {
	for i, interfaceValue := range interfaces {
		if input == interfaceValue {
			return i
		}
	}

	return 0
}

// ShellQuote always single-quotes s for bash.
func ShellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
