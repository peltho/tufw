package utils

import (
	"bytes"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

func FormatUfwRule(input string) string {
	r := input

	// 1. Normalize rule numbers [ 1] -> [1]
	re1 := regexp.MustCompile(`\[\s*([0-9]+)\]`)
	r = re1.ReplaceAllString(r, `[$1]`)

	// 2. Remove (out)
	re2 := regexp.MustCompile(`\(out\)`)
	r = re2.ReplaceAllString(r, "")

	// 3. Remove "(v6)" suffixes
	re3 := regexp.MustCompile(`(\w)\s*\(v6\)`)
	r = re3.ReplaceAllString(r, `$1`)

	// 4. Convert "ALLOW IN" etc. -> "ALLOW-IN"
	re4 := regexp.MustCompile(`\b(ALLOW|DENY|LIMIT|REJECT)\s+(IN|OUT|FWD)\b`)
	r = re4.ReplaceAllString(r, `$1-$2`)

	// --- Handle normal "IN on <iface> from any to <ip> proto <proto> port <n>" rules ---
	reInboundIface := regexp.MustCompile(`(\[\d+\])\s+(?:to\s+)?(\S+)\s+(\d+/\w+)\s+([A-Z]{2,}-IN)\s+(?:from\s+(?:Anywhere|any)\s+)?on\s+(\S+)`)
	if reInboundIface.MatchString(r) {
		r = reInboundIface.ReplaceAllString(r, `$1 $2 $3 $4 Anywhere_on_$5`)
	}

	// Handle FWD rules
	/*reRoute := regexp.MustCompile(`(\[\d+\])\s+(\S+)\s+(\d+)(/\w+)?\s+([A-Z]{2,})\s+FWD\s+(\S+)\s+on\s+(\S+)\s+out\s+on\s+(\S+)(?:\s+#\s*(.*))?`)
	if reRoute.MatchString(r) {
		r = reRoute.ReplaceAllString(r, `$1 $2$4 $3 $5-FWD $6_on_$7_out_on_$8 # $9`)
		return strings.TrimSpace(strings.ReplaceAll(r, "  ", " "))
	}*/

	// 5. Handle proto (left or right)"
	reProtoLeft := regexp.MustCompile(`(\[\d+\])\s+([0-9./]+)\s*-\s*(udp|tcp)\s+([A-Z-]+)\s+(.*)`)
	r = reProtoLeft.ReplaceAllString(r, `$1 $2/$3 - $4 $5`)

	reProtoRight := regexp.MustCompile(`(\[\d+\])\s+(Anywhere|any)\s*-\s*(udp|tcp)\s+([A-Z-]+)\s+([0-9./]+)`)
	r = reProtoRight.ReplaceAllString(r, `$1 $2/$3 - $4 $5`)

	// 6. Anywhere rules with numbers
	//re6 := regexp.MustCompile(`(\]\s+)([0-9]{2,})\s([A-Z]{2,}(-[A-Z]{2,3})?)`)
	//r = re6.ReplaceAllString(r, `$1Anywhere $2 $3`)

	// 7. IPv4 rules with protocol (no “- udp” form)
	re7 := regexp.MustCompile(`(\]\s+)(([0-9]{1,3}\.){3}[0-9]{1,3}(/\d{1,2})?)\s([A-Z]{2,}-[A-Z]{2,3})`)
	r = re7.ReplaceAllString(r, `$1$2 - $5`)

	// 8. Port/protocol adjustments (e.g., port 80/tcp)
	re8 := regexp.MustCompile(`(\]\s+)(.*)\s([0-9]+)(/\w{3})`)
	r = re8.ReplaceAllString(r, `$1$2$4 $3`)

	// 9. Remove "/proto" short notation errors
	re9 := regexp.MustCompile(`(\]\s+)/([a-z]{3})\s`)
	r = re9.ReplaceAllString(r, `$1$2 `)

	// Collapse multiple spaces
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
	r := regexp.MustCompile(`.+_on_(.+)`)
	matches := r.FindStringSubmatch(strings.TrimSpace(input))
	index := 0

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

	r := regexp.MustCompile(`(.*)/tcp|udp`)
	matches := r.FindStringSubmatch(s)
	if len(matches) > 1 {
		s = matches[1]
	}

	return s, ""
}
