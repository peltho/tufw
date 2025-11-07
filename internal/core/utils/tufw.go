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
	row = regexp.MustCompile(`\s+`).ReplaceAllString(row, " ")
	row = regexp.MustCompile(`\[ ?(\d+)\]`).ReplaceAllString(row, "[$1]")

	removeV6 := regexp.MustCompile(`(\w)\s*\(v6\)`)
	row = removeV6.ReplaceAllString(row, `$1`)

	// --- Extract index ---
	reIndex := regexp.MustCompile(`^\[(\d+)\]`)
	index := ""
	if m := reIndex.FindStringSubmatch(row); len(m) > 1 {
		index = "[" + m[1] + "]"
		row = strings.TrimSpace(reIndex.ReplaceAllString(row, ""))
	}

	// --- Extract comment ---
	comment := ""
	if idx := strings.Index(row, "#"); idx != -1 {
		comment = " " + strings.TrimSpace(row[idx:])
		row = strings.TrimSpace(row[:idx])
	}

	// --- Interfaces ---
	var outIface, inIface string

	// Case 1: explicit "out on"
	if strings.Contains(row, " out on ") {
		re := regexp.MustCompile(`on ([^\s]+) out on ([^\s]+)`)
		if m := re.FindStringSubmatch(row); len(m) > 2 {
			inIface = m[1]
			outIface = m[2]
		}
		row = re.ReplaceAllString(row, "")
	} else {
		// Case 2: generic "on"
		onRe := regexp.MustCompile(`\bon\s+([^\s]+)`)
		matches := onRe.FindAllStringSubmatch(row, -1)
		// Basic rule with an interface IN
		if len(matches) > 0 {
			inIface = matches[0][1]
		}
		// FWD rule with interface IN and OUT (overriding above)
		if len(matches) > 1 {
			inIface = matches[1][1]
			outIface = matches[0][1]
		}
		row = onRe.ReplaceAllString(row, "")
	}

	row = strings.TrimSpace(regexp.MustCompile(`\s+`).ReplaceAllString(row, " "))
	tokens := strings.Fields(row)
	if len(tokens) < 3 {
		return fmt.Sprintf("%s %s", index, row)
	}

	// --- Find ALLOW / DENY ---
	actionIdx := -1
	for i, t := range tokens {
		if t == "ALLOW" || t == "DENY" {
			actionIdx = i
			break
		}
	}
	if actionIdx == -1 {
		return fmt.Sprintf("%s %s", index, row)
	}

	// --- Direction ---
	direction := ""
	if actionIdx+1 < len(tokens) {
		if dir := tokens[actionIdx+1]; dir == "IN" || dir == "OUT" || dir == "FWD" {
			direction = dir
		}
	}
	actionFull := tokens[actionIdx]
	if direction != "" {
		actionFull += "-" + direction
	}

	// --- Split sides ---
	toTokens := tokens[:actionIdx]
	fromTokens := []string{}
	if actionIdx+2 < len(tokens) && (tokens[actionIdx+1] == "IN" || tokens[actionIdx+1] == "OUT" || tokens[actionIdx+1] == "FWD") {
		fromTokens = tokens[actionIdx+2:]
	} else if actionIdx+1 < len(tokens) {
		fromTokens = tokens[actionIdx+1:]
	}

	toPart := strings.Join(toTokens, " ")
	fromPart := strings.Join(fromTokens, " ")

	// --- Port / protocol ---
	port := "-"
	proto := ""
	rePortProto := regexp.MustCompile(`^(\S+)\s+(\d+)(?:/(\S+))?$`)
	reDashProto := regexp.MustCompile(`^(\S+)\s+-\s+(\S+)$`)

	if m := rePortProto.FindStringSubmatch(toPart); len(m) > 0 {
		toPart = m[1]
		port = m[2]
		proto = m[3]
	} else if m := reDashProto.FindStringSubmatch(toPart); len(m) > 0 {
		toPart = m[1]
		port = "-"
		proto = m[2]
	} else if strings.Contains(toPart, "/tcp") || strings.Contains(toPart, "/udp") {
		if !strings.Contains(toPart, " ") {
			// ok
		} else {
			parts := strings.SplitN(toPart, " ", 2)
			toPart = parts[0]
			port = parts[1]
		}
	}
	if proto != "" {
		toPart += "/" + proto
	}

	if port == "-" {
		// If toPart is a pure number, it's actually the port
		if regexp.MustCompile(`^\d+$`).MatchString(toPart) {
			port = toPart
			toPart = ""
		}
	}

	// --- Attach interfaces ---
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
	r := regexp.MustCompile(`(.*)_on_(.*)`)
	matches := r.FindStringSubmatch(input)

	if len(matches) > 2 {
		for i, interfaceValue := range interfaces {
			if matches[2] == interfaceValue {
				return i
			}
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
