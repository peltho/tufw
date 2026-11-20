package utils

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"

	"github.com/peltho/tufw/internal/core/domain"
)

const tuplePrefix = "### tuple ###"

// ParseRulesFile extracts the rules from the content of a ufw user.rules or
// user6.rules file. It mirrors UFWBackendIptables._read_rules from ufw:
//
//	### tuple ### <action> <proto> <dport> <dst> <sport> <src> [<dapp> <sapp>] <dir>[_iface] [comment=<hex>]
//
// where <action> may be prefixed by "route:" and suffixed by "_log" or
// "_log-all", <dir> is "in", "out", "in_eth0", "out_eth0" or
// "in_eth0!out_eth1", app names have spaces encoded as %20 ("-" if unset)
// and comments are hex-encoded UTF-8. Malformed tuples are skipped, as ufw does.
func ParseRulesFile(content string, v6 bool) []domain.Rule {
	var rules []domain.Rule

	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimRight(line, "\r")
		if !strings.HasPrefix(line, tuplePrefix) {
			continue
		}

		// comment= is always last
		comment := ""
		if i := strings.Index(line, " comment="); i != -1 {
			comment = hexDecode(strings.TrimSpace(line[i+len(" comment="):]))
			line = line[:i]
		}

		f := strings.Fields(strings.TrimPrefix(line, tuplePrefix))
		if len(f) < 6 || len(f) > 9 {
			continue
		}

		r := domain.Rule{
			Protocol:  f[1],
			DPort:     f[2],
			Dst:       f[3],
			SPort:     f[4],
			Src:       f[5],
			Direction: "in", // old 6/8 field format has no direction
			Comment:   comment,
			V6:        v6,
		}

		action := f[0]
		if after, ok := strings.CutPrefix(action, "route:"); ok {
			r.Forward = true
			action = after
		}
		r.Action, r.LogType, _ = strings.Cut(action, "_")

		if len(f) == 7 || len(f) == 9 {
			last := f[len(f)-1]
			r.Direction, _, _ = strings.Cut(last, "_")
			if strings.Contains(last, "_") {
				switch {
				case strings.Contains(last, "!"):
					in, out, _ := strings.Cut(last, "!")
					_, r.IfaceIn, _ = strings.Cut(in, "_")
					_, r.IfaceOut, _ = strings.Cut(out, "_")
				case strings.HasPrefix(last, "in_"):
					r.IfaceIn = strings.TrimPrefix(last, "in_")
				case strings.HasPrefix(last, "out_"):
					r.IfaceOut = strings.TrimPrefix(last, "out_")
				default:
					continue
				}
			}
		}

		if len(f) >= 8 {
			if f[6] != "-" {
				r.DApp = strings.ReplaceAll(f[6], "%20", " ")
			}
			if f[7] != "-" {
				r.SApp = strings.ReplaceAll(f[7], "%20", " ")
			}
		}

		rules = append(rules, r)
	}

	return rules
}

// hexDecode mirrors ufw.util.hex_decode: odd-length input is truncated by one.
func hexDecode(h string) string {
	if len(h)%2 == 1 {
		h = h[:len(h)-1]
	}
	b, err := hex.DecodeString(h)
	if err != nil {
		return h
	}
	return string(b)
}

// AppTupleKey mirrors UFWRule.get_app_tuple. An app profile covering several
// ports is stored as several tuples; ufw shows (and numbers) them once.
// Returns "" for non-app rules.
func AppTupleKey(r domain.Rule) string {
	if r.DApp == "" && r.SApp == "" {
		return ""
	}

	key := fmt.Sprintf("%s %s %s %s", r.DApp, r.Dst, r.SApp, r.Src)
	if r.DApp == "" {
		key = fmt.Sprintf("%s %s %s %s", r.DPort, r.Dst, r.SApp, r.Src)
	}
	if r.SApp == "" {
		key = fmt.Sprintf("%s %s %s %s", r.DApp, r.Dst, r.SPort, r.Src)
	}

	if r.IfaceIn == "" && r.IfaceOut == "" {
		key += " " + r.Direction
	} else {
		if r.IfaceIn != "" {
			key += " in_" + r.IfaceIn
		}
		if r.IfaceOut != "" {
			key += " out_" + r.IfaceOut
		}
	}

	return key
}

// NumberRules merges IPv4 and IPv6 rules and assigns the numbers shown by
// `ufw status numbered` (IPv4 first, then IPv6, duplicate app tuples
// collapsed). Mirrors UFWBackend.get_rule_by_number.
func NumberRules(v4, v6 []domain.Rule) []domain.Rule {
	all := append(append([]domain.Rule{}, v4...), v6...)
	seen := map[string]bool{}
	numbered := make([]domain.Rule, 0, len(all))

	n := 1
	for _, r := range all {
		if key := AppTupleKey(r); key != "" {
			if seen[key] {
				continue
			}
			seen[key] = true
		}
		r.Number = n
		n++
		numbered = append(numbered, r)
	}

	return numbered
}

var numberedLine = regexp.MustCompile(`(?m)^\[\s*\d+\]`)

// CountNumberedRules counts the rules listed in `ufw status numbered` output.
func CountNumberedRules(statusOutput string) int {
	return len(numberedLine.FindAllString(statusOutput, -1))
}

// IPv6Enabled reads the IPV6= setting from /etc/default/ufw content
// (ufw defaults to yes).
func IPv6Enabled(defaults string) bool {
	for _, line := range strings.Split(defaults, "\n") {
		line = strings.TrimSpace(line)
		if v, ok := strings.CutPrefix(line, "IPV6="); ok {
			return strings.ToLower(strings.Trim(v, `"'`)) == "yes"
		}
	}
	return true
}

func isAnywhere(addr string) bool {
	return addr == "0.0.0.0/0" || addr == "::/0"
}

func displayAddr(addr string, v6 bool) string {
	if isAnywhere(addr) {
		if v6 {
			return "Anywhere (v6)"
		}
		return "Anywhere"
	}
	return addr
}

// RuleCells formats a rule for the table, placing interfaces like
// `ufw status` does: for route rules the incoming interface goes under From
// and the outgoing one under To, for other rules the reverse.
func RuleCells(r domain.Rule) domain.CellValues {
	to := displayAddr(r.Dst, r.V6)
	from := displayAddr(r.Src, r.V6)

	toIface, fromIface := r.IfaceIn, r.IfaceOut
	if r.Forward {
		toIface, fromIface = r.IfaceOut, r.IfaceIn
	}
	if toIface != "" {
		to += " on " + toIface
	}
	if fromIface != "" {
		from += " on " + fromIface
	}

	if r.SApp != "" {
		from += " (" + r.SApp + ")"
	} else if r.SPort != "any" && r.SPort != "" {
		from += " port " + r.SPort
	}

	port := "-"
	if r.DApp != "" {
		port = r.DApp
	} else if r.DPort != "any" && r.DPort != "" {
		port = r.DPort
	}

	// Like ufw, hide the protocol of app rules: one numbered app rule may
	// cover several tuples with different protocols.
	proto := "-"
	if r.Protocol != "any" && r.Protocol != "" && r.DApp == "" && r.SApp == "" {
		proto = r.Protocol
	}

	dir := strings.ToUpper(r.Direction)
	if r.Forward {
		dir = "FWD"
	}
	action := strings.ToUpper(r.Action) + "-" + dir
	if r.LogType != "" {
		action += " (" + r.LogType + ")"
	}

	return domain.CellValues{
		Index:   fmt.Sprintf("[%d]", r.Number),
		To:      to,
		Port:    port,
		Proto:   proto,
		Action:  action,
		From:    from,
		Comment: r.Comment,
	}
}

// RuleSearchText is the text the search regex is matched against.
func RuleSearchText(r domain.Rule) string {
	c := RuleCells(r)
	return strings.Join([]string{c.Index, c.To, c.Port, c.Proto, c.Action, c.From, c.Comment}, " ")
}

var safeShellArg = regexp.MustCompile(`^[A-Za-z0-9_.:/,%@+=-]+$`)

// ShellArg quotes s for bash when it contains anything beyond plain
// address/port characters.
func ShellArg(s string) string {
	if safeShellArg.MatchString(s) {
		return s
	}
	return ShellQuote(s)
}
