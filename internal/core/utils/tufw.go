package utils

import (
	"bytes"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"github.com/peltho/tufw/internal/core/domain"
)

func FormatUfwRule(row string) string {
	row = strings.TrimSpace(row)
	row = regexp.MustCompile(`\s+`).ReplaceAllString(row, " ")            // normalize spaces
	row = regexp.MustCompile(`\[ ?(\d+)\]`).ReplaceAllString(row, "[$1]") // normalize index

	// Extract comment part
	comment := ""
	if idx := strings.Index(row, "#"); idx != -1 {
		comment = " " + strings.TrimSpace(row[idx:])
		row = strings.TrimSpace(row[:idx])
	}

	// Extract interface info
	var inIface, outIface string
	// Detect and remove "out on <iface>"
	if strings.Contains(row, " out on ") {
		re := regexp.MustCompile(`out on ([^\s]+)`)
		if m := re.FindStringSubmatch(row); len(m) > 1 {
			outIface = m[1]
		}
		row = re.ReplaceAllString(row, "")
	}

	// Detect and remove "on <iface>" (any rule may have this)
	if strings.Contains(row, " on ") {
		re := regexp.MustCompile(` on ([^\s]+)`)
		if m := re.FindStringSubmatch(row); len(m) > 1 {
			inIface = m[1]
		}
		row = re.ReplaceAllString(row, "")
	}

	row = regexp.MustCompile(`\s+`).ReplaceAllString(row, " ")
	tokens := strings.Fields(row)
	if len(tokens) < 3 {
		return row
	}

	index := tokens[0]
	tokens = tokens[1:]

	// Locate ALLOW or DENY
	actionIdx := -1
	for i, t := range tokens {
		if t == "ALLOW" || t == "DENY" {
			actionIdx = i
			break
		}
	}
	if actionIdx == -1 {
		return row
	}

	// Determine direction (IN/OUT/FWD)
	direction := ""
	if actionIdx+1 < len(tokens) {
		next := tokens[actionIdx+1]
		if next == "IN" || next == "OUT" || next == "FWD" {
			direction = next
		}
	}

	actionFull := tokens[actionIdx]
	if direction != "" {
		actionFull += "-" + direction
	}

	// Split into parts
	toTokens := tokens[:actionIdx]
	fromTokens := []string{}
	if direction != "" && actionIdx+2 < len(tokens) {
		fromTokens = tokens[actionIdx+2:]
	} else if actionIdx+1 < len(tokens) {
		fromTokens = tokens[actionIdx+1:]
	}
	fromPart := strings.Join(fromTokens, " ")

	// Detect IP/port/protocol in 'to' part
	toPart := strings.Join(toTokens, " ")
	protocol := ""
	port := "-"

	reProto := regexp.MustCompile(`^(\S+)\s+(\d+)(?:/(\S+))?$`)
	reDashProto := regexp.MustCompile(`^(\S+)\s+-\s+(\S+)$`)

	if m := reProto.FindStringSubmatch(toPart); len(m) > 0 {
		toPart = m[1]
		port = m[2]
		protocol = m[3]
	} else if m := reDashProto.FindStringSubmatch(toPart); len(m) > 0 {
		toPart = m[1]
		port = "-"
		protocol = m[2]
	} else if strings.Contains(toPart, "/tcp") || strings.Contains(toPart, "/udp") {
		// already embedded
		parts := strings.SplitN(toPart, " ", 2)
		toPart = parts[0]
		if len(parts) > 1 {
			port = parts[1]
		}
	}

	if protocol != "" {
		toPart += "/" + protocol
	}

	// Interface rules:
	// - if we have outIface → attach to "to" side
	// - if we have inIface → attach to "from" side
	if outIface != "" {
		toPart += "_on_" + outIface
	}
	if inIface != "" {
		fromPart += "_on_" + inIface
	}

	formatted := fmt.Sprintf("%s %s %s %s %s%s",
		index, strings.TrimSpace(toPart), port, actionFull, strings.TrimSpace(fromPart), comment)

	formatted = strings.TrimSpace(regexp.MustCompile(`\s+`).ReplaceAllString(formatted, " "))
	return formatted
}

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
	for i, interfaceValue := range interfaces {
		if input == interfaceValue {
			return i
		}
	}

	return 0
}

func ParseFromOrTo(input string) (address, proto, iface string) {
	input = strings.ReplaceAll(input, " ", "_")
	address, proto, iface = "", "", ""

	// 1. Extract interface
	if idx := strings.Index(input, "_on_"); idx != -1 {
		iface = input[idx+len("_on_"):]
		input = input[:idx]
	}

	// 2. Extract protocol
	for _, p := range []string{"tcp", "udp"} {
		if idx := strings.LastIndex(input, "/"+p); idx != -1 {
			address = input[:idx]
			proto = p
			return
		}
	}

	// 3. No protocol
	address = input
	return
}

func FillCell(row string) *domain.CellValues {
	cols := strings.Fields(row)

	// --- extract comment ---
	commentText := ""
	for i, tok := range cols {
		if strings.HasPrefix(tok, "#") {
			commentText = strings.Join(cols[i+1:], " ")
			cols = cols[:i]
			break
		}
	}

	if len(cols) == 0 {
		return nil
	}

	// --- index ---
	idx := cols[0]

	toField := cols[1]
	portField := cols[2]
	if len(cols) == 4 {
		toField = "Anywhere"
		portField = cols[1]
	}

	proto := ""
	address, proto, ifaceOut := ParseFromOrTo(toField)

	toDisplay := address
	if proto != "" {
		toDisplay = fmt.Sprintf("%s/%s", address, proto)
	}
	if ifaceOut != "" {
		toDisplay = fmt.Sprintf("%s_on_%s", toDisplay, ifaceOut)
	}

	if toDisplay == "" {
		toDisplay = "-"
	}

	// --- Action (ALLOW-IN, DENY-FWD, etc.) ---
	actionField := ""
	actionIdx := -1
	for i, tok := range cols[2:] {
		if matched, _ := regexp.MatchString(`^(ALLOW|DENY|LIMIT|REJECT)(-IN|-OUT|-FWD)?$`, tok); matched {
			actionField = tok
			actionIdx = i + 2
			break
		}
	}

	// --- Port (if separate) ---
	if actionIdx > 2 && actionIdx < len(cols) {
		for i := 2; i < actionIdx; i++ {
			if _, err := strconv.Atoi(cols[i]); err == nil {
				portField = cols[i]
			}
		}
	}

	// --- From and iface ---
	fromField := "Anywhere"
	if actionIdx >= 0 && actionIdx+1 < len(cols) {
		fromField = cols[actionIdx+1]
	}

	fromField, _, ifaceIn := ParseFromOrTo(fromField)
	fromDisplay := fromField
	if ifaceIn != "" {
		fromDisplay = fmt.Sprintf("%s_on_%s", fromField, ifaceIn)
	}

	if portField == "" {
		portField = "-"
	}

	return &domain.CellValues{
		Index:   idx,
		To:      toDisplay,
		Port:    portField,
		Action:  actionField,
		From:    fromDisplay,
		Comment: commentText,
	}
}
