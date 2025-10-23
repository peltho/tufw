package utils

import (
	"bytes"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

func Shellout(command string) (error, string, string) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd := exec.Command("bash", "-c", command)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return err, stdout.String(), stderr.String()
}

func ValidatePort(text string, ch rune) bool {
	_, err := strconv.Atoi(text)
	return err == nil
}

func ParseIPAddress(input string) string {
	r := regexp.MustCompile(`(([0-9]{1,3}\.){3}[0-9]{1,3})(/[0-9]{1,2})?`)
	matches := r.FindStringSubmatch(input)
	value := ""
	if len(matches) > 0 {
		value = matches[0]
	}
	return value
}

func ParseProtocol(inputs ...string) string {
	r := regexp.MustCompile(`/?(tcp|udp)`)
	value := ""
	for _, input := range inputs {
		matches := r.FindStringSubmatch(input)
		if len(matches) > 1 {
			return matches[1]
		}
	}

	return value
}

func ParsePort(input string) string {
	r := regexp.MustCompile(`([0-9]*)(/[a-z]{3})?`)
	value := ""
	matches := r.FindStringSubmatch(input)
	if len(matches) > 0 {
		value = matches[1]
	}

	return value
}

func ParseInterfaceIndex(input string, interfaces []string) int {
	r := regexp.MustCompile(`.+ on (.+)`)
	matches := r.FindStringSubmatch(strings.TrimSpace(input))
	index := len(interfaces) - 1

	if len(matches) == 0 {
		return index
	}

	for i, interfaceValue := range interfaces {
		if matches[1] == interfaceValue {
			return i
		}
	}

	return index
}

func SplitValueWithIface(s string) (val, iface string) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "(") && strings.HasSuffix(s, ")") {
		open := strings.LastIndex(s, "(")
		close := strings.LastIndex(s, ")")
		if open != -1 && close > open {
			val = strings.TrimSpace(s[:open])
			iface = strings.TrimSpace(s[open+1 : close])
			return
		}
	}
	return s, ""
}
