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

func FormatUfwRule(input string) string {
	r := input

	// 1. Normalize rule numbers [ 1] -> [1]
	re1 := regexp.MustCompile(`\[\s*([0-9]+)\]`)
	r = re1.ReplaceAllString(r, `[$1]`)

	// 2. Remove (out)
	r = strings.ReplaceAll(r, "(out)", "")

	// 3. Remove "(v6)" suffixes
	re3 := regexp.MustCompile(`\s*\(v6\)`)
	r = re3.ReplaceAllString(r, "")

	// 4. Convert "ALLOW IN" etc. -> "ALLOW-IN"
	re4 := regexp.MustCompile(`\b(ALLOW|DENY|LIMIT|REJECT)\s+(IN|OUT|FWD)\b`)
	r = re4.ReplaceAllString(r, `$1-$2`)

	reFwd := regexp.MustCompile(
		`(\[\d+\])\s+(\S+)` + // index, to
			`(?:\s+(\d+)/(tcp|udp))?` + // optional port/proto
			`\s+([A-Z-]+)\s+(\S+)\s+on\s+(\S+)\s+out\s+on\s+(\S+)` + // action, from, in/out iface
			`(?:\s+#\s*(.*))?`) // optional comment

	if reFwd.MatchString(r) {
		matches := reFwd.FindStringSubmatch(r)
		idx := matches[1]
		to := matches[2]
		port := matches[3]
		proto := matches[4]
		action := matches[5]
		from := matches[6]
		inIface := matches[7]
		outIface := matches[8]
		comment := matches[9]

		toDisplay := to
		if proto != "" {
			toDisplay = fmt.Sprintf("%s/%s", to, proto)
		}
		if outIface != "" {
			toDisplay = fmt.Sprintf("%s_on_%s", toDisplay, outIface)
		}

		fromDisplay := from
		if inIface != "" {
			fromDisplay = fmt.Sprintf("%s_on_%s", from, inIface)
		}

		if port != "" {
			r = fmt.Sprintf("%s %s %s %s %s", idx, toDisplay, port, action, fromDisplay)
		} else {
			r = fmt.Sprintf("%s %s - %s %s", idx, toDisplay, action, fromDisplay)
		}

		if comment != "" {
			r += " # " + strings.TrimSpace(comment)
		}

		return strings.Join(strings.Fields(r), " ")
	}

	// 5. Handle proto on the left (e.g. "10.0.0.0/24 - udp")
	reProtoLeft := regexp.MustCompile(`(\[\d+\])\s+([0-9./]+)\s*-\s*(udp|tcp)\s+([A-Z-]+)\s+(.*)`)
	r = reProtoLeft.ReplaceAllString(r, `$1 $2/$3 - $4 $5`)

	// 6. Handle proto on the right ("Anywhere - udp ...")
	reProtoRight := regexp.MustCompile(`(\[\d+\])\s+(Anywhere|any)\s*-\s*(udp|tcp)\s+([A-Z-]+)\s+([0-9./]+)`)
	r = reProtoRight.ReplaceAllString(r, `$1 $2/$3 - $4 $5`)

	// 7. IPv4 rules with protocol but no “- udp” part
	re7 := regexp.MustCompile(`(\]\s+)(([0-9]{1,3}\.){3}[0-9]{1,3}(/\d{1,2})?)\s([A-Z]{2,}-[A-Z]{2,3})`)
	r = re7.ReplaceAllString(r, `$1$2 - $5`)

	// 8. Port/protocol adjustments (e.g., "443/tcp" → " /tcp 443")
	re8 := regexp.MustCompile(`(\]\s+)(.*)\s([0-9]+)(/\w{3})`)
	r = re8.ReplaceAllString(r, `$1$2$4 $3`)

	// 9. Remove extra "/proto" errors
	re9 := regexp.MustCompile(`(\]\s+)/([a-z]{3})\s`)
	r = re9.ReplaceAllString(r, `$1$2 `)

	// Clean up spacing
	r = strings.Join(strings.Fields(r), " ")
	return r
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
