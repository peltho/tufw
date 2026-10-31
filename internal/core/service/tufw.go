// Package service reads ufw rules and applies changes through the ufw CLI.
// It knows nothing about the terminal UI.
package service

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/peltho/tufw/internal/core/domain"
	"github.com/peltho/tufw/internal/core/utils"
)

var (
	// Overridable in tests.
	shellout   = utils.Shellout
	readFile   = os.ReadFile
	interfaces = net.Interfaces

	// ufw >= 0.34 keeps user rules in /etc/ufw, older releases in /lib/ufw.
	rulesFileLocations = [][2]string{
		{"/etc/ufw/user.rules", "/etc/ufw/user6.rules"},
		{"/lib/ufw/user.rules", "/lib/ufw/user6.rules"},
	}
	ufwDefaultsFile = "/etc/default/ufw"
)

// Actions the rule form offers, as "<ACTION> <DIRECTION>".
var ActionOptions = []string{"ALLOW IN", "DENY IN", "REJECT IN", "LIMIT IN", "ALLOW OUT", "DENY OUT", "REJECT OUT", "LIMIT OUT", "ALLOW FWD", "DENY FWD"}

var (
	// ErrEmptyRule is returned when the form would create an "any to any" rule.
	ErrEmptyRule = errors.New("fill in at least one of To, Port, Protocol, Interface or From")
	// ErrInvalidRule wraps ufw's message when `ufw --dry-run` rejects a rule.
	ErrInvalidRule = errors.New("invalid rule")
)

// Firewall talks to ufw. It is stateless: every call reads ufw's files
// again, so it can safely run from background commands.
type Firewall struct{}

func New() *Firewall {
	return &Firewall{}
}

// LoadRules reads the rules ufw stores in user.rules and user6.rules and
// numbers them the way `ufw status numbered` does.
func (f *Firewall) LoadRules() ([]domain.Rule, error) {
	var v4Content, v6Path string
	var lastErr error
	found := false
	for _, loc := range rulesFileLocations {
		b, err := readFile(loc[0])
		if err != nil {
			lastErr = err
			continue
		}
		v4Content, v6Path, found = string(b), loc[1], true
		break
	}
	if !found {
		return nil, fmt.Errorf("cannot read ufw rules file: %w", lastErr)
	}

	v4 := utils.ParseRulesFile(v4Content, false)

	ipv6 := true
	if b, err := readFile(ufwDefaultsFile); err == nil {
		ipv6 = utils.IPv6Enabled(string(b))
	}

	var v6 []domain.Rule
	if ipv6 {
		b, err := readFile(v6Path)
		if err != nil {
			return nil, fmt.Errorf("cannot read ufw IPv6 rules file: %w", err)
		}
		v6 = utils.ParseRulesFile(string(b), true)
	}

	return utils.NumberRules(v4, v6), nil
}

// Interfaces lists the network interface names.
func (f *Firewall) Interfaces() []string {
	ifaces, err := interfaces()
	if err != nil {
		log.Printf("cannot list interfaces: %v", err)
		return nil
	}
	names := make([]string, 0, len(ifaces))
	for _, i := range ifaces {
		names = append(names, i.Name)
	}
	return names
}

// IsActive reports whether ufw is enabled.
func (f *Firewall) IsActive() (bool, error) {
	out, trace, err := shellout("ufw status")
	if err != nil {
		return false, fmt.Errorf("ufw status failed: %s", strings.TrimSpace(trace))
	}
	return strings.Contains(out, "Status: active"), nil
}

func (f *Firewall) run(cmd string) error {
	if _, trace, err := shellout(cmd); err != nil {
		return fmt.Errorf("%s failed: %s", cmd, strings.TrimSpace(trace))
	}
	log.Print(cmd)
	return nil
}

func (f *Firewall) Enable() error  { return f.run("ufw --force enable") }
func (f *Firewall) Disable() error { return f.run("ufw --force disable") }
func (f *Firewall) Reset() error   { return f.run("ufw --force reset") }

// checkRuleNumber must pass before any command addressing a rule by number
// (delete, insert). It reloads the rules, checks that our numbering agrees
// with ufw's own (`ufw status numbered`) and that the rule at that number is
// still the one the user selected. Returns the freshly loaded rules.
func (f *Firewall) checkRuleNumber(selected domain.Rule) ([]domain.Rule, error) {
	rules, err := f.LoadRules()
	if err != nil {
		return nil, err
	}

	out, trace, err := shellout("ufw status numbered")
	if err != nil {
		return nil, fmt.Errorf("ufw status numbered failed: %s", strings.TrimSpace(trace))
	}
	if strings.Contains(out, "Status: inactive") {
		return nil, errors.New("ufw is inactive, rule numbers cannot be verified")
	}
	if n := utils.CountNumberedRules(out); n != len(rules) {
		return nil, fmt.Errorf("ufw lists %d rules but the rule files contain %d, refusing to modify rules by number", n, len(rules))
	}
	if selected.Number < 1 || selected.Number > len(rules) || rules[selected.Number-1] != selected {
		return nil, fmt.Errorf("rule [%d] changed since it was loaded, reload and try again", selected.Number)
	}

	return rules, nil
}

// Create appends a rule. Returns the ufw command that was applied.
func (f *Firewall) Create(fv domain.FormValues) (string, error) {
	if isEmptyRule(fv) {
		return "", ErrEmptyRule
	}

	args, err := buildRuleArgs(fv, 0)
	if err != nil {
		return "", err
	}
	if err := dryRun(args); err != nil {
		return "", err
	}

	cmd := "ufw " + args
	return cmd, f.run(cmd)
}

// Edit replaces rule with fv, keeping its position. Returns the ufw command
// that was applied.
func (f *Firewall) Edit(rule domain.Rule, fv domain.FormValues) (string, error) {
	if isEmptyRule(fv) {
		return "", ErrEmptyRule
	}

	rules, err := f.checkRuleNumber(rule)
	if err != nil {
		return "", err
	}

	// After deleting the last rule there is nothing left to insert before.
	insertAt := 0
	if rule.Number < len(rules) {
		insertAt = rule.Number
	}

	args, err := buildRuleArgs(fv, insertAt)
	if err != nil {
		return "", err
	}

	// Validate the new rule before touching the old one
	if err := dryRun(args); err != nil {
		return "", err
	}

	if err := f.run(fmt.Sprintf("ufw --force delete %d", rule.Number)); err != nil {
		return "", err
	}

	cmd := "ufw " + args
	if err := f.run(cmd); err != nil {
		return "", fmt.Errorf("rule [%d] was deleted but its replacement failed: %w", rule.Number, err)
	}
	return cmd, nil
}

// Delete removes rule after checking its number is still accurate.
func (f *Firewall) Delete(rule domain.Rule) error {
	if _, err := f.checkRuleNumber(rule); err != nil {
		return err
	}
	return f.run(fmt.Sprintf("ufw --force delete %d", rule.Number))
}

func dryRun(args string) error {
	if _, trace, err := shellout("ufw --dry-run " + args); err != nil {
		msg := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(trace), "ERROR:"))
		return fmt.Errorf("%w: %s", ErrInvalidRule, msg)
	}
	return nil
}

// FilterRules keeps the rules whose displayed text matches needle, a case
// insensitive regex (matched literally if it doesn't compile).
func FilterRules(rules []domain.Rule, needle string) []domain.Rule {
	if needle == "" {
		return rules
	}
	re, err := regexp.Compile("(?i)" + needle)
	if err != nil {
		re = regexp.MustCompile("(?i)" + regexp.QuoteMeta(needle))
	}

	matches := []domain.Rule{}
	for _, rule := range rules {
		if re.MatchString(utils.RuleSearchText(rule)) {
			matches = append(matches, rule)
		}
	}
	return matches
}

// RuleToFormValues converts a rule into form values, or explains why the
// form can't represent it (editing it would silently drop parts of the rule).
func RuleToFormValues(r domain.Rule) (domain.FormValues, error) {
	unsupported := func(what string) error {
		return fmt.Errorf("rule [%d] uses %s, which the editor doesn't support yet; use the ufw CLI to change it", r.Number, what)
	}

	switch {
	case r.DApp != "" || r.SApp != "":
		return domain.FormValues{}, unsupported("an application profile")
	case r.SPort != "any" && r.SPort != "":
		return domain.FormValues{}, unsupported("a source port")
	case r.LogType != "":
		return domain.FormValues{}, unsupported("logging")
	}

	proto := r.Protocol
	if proto == "any" {
		proto = ""
	}
	if proto != "" && proto != "tcp" && proto != "udp" {
		return domain.FormValues{}, unsupported("protocol " + proto)
	}

	dir := strings.ToUpper(r.Direction)
	if r.Forward {
		dir = "FWD"
	}
	action := strings.ToUpper(r.Action) + " " + dir
	known := false
	for _, a := range ActionOptions {
		known = known || a == action
	}
	if !known {
		return domain.FormValues{}, unsupported("action " + action)
	}

	fv := domain.FormValues{
		Action:   action,
		Protocol: proto,
		Comment:  r.Comment,
	}
	if r.DPort != "any" {
		fv.Port = r.DPort
	}
	if r.Dst != "0.0.0.0/0" && r.Dst != "::/0" {
		fv.To = r.Dst
	}
	if r.Src != "0.0.0.0/0" && r.Src != "::/0" {
		fv.From = r.Src
	}

	switch {
	case r.Forward:
		fv.Interface, fv.InterfaceOut = r.IfaceIn, r.IfaceOut
	case r.Direction == "out":
		fv.Interface = r.IfaceOut
	default:
		fv.Interface = r.IfaceIn
	}

	return fv, nil
}

// IsForwardAction reports whether an action ("ALLOW FWD", "deny-fwd"...)
// creates a route rule.
func IsForwardAction(action string) bool {
	return strings.HasSuffix(strings.ToLower(action), "fwd")
}

func isEmptyRule(fv domain.FormValues) bool {
	return fv.Port == "" && fv.Protocol == "" && fv.Interface == "" && fv.To == "" && fv.From == ""
}

func orAny(s string) string {
	if s == "" || strings.HasPrefix(s, "Anywhere") {
		return "any"
	}
	return s
}

// buildRuleArgs turns form values into ufw arguments (without the leading
// "ufw"). insertAt > 0 inserts the rule at that position.
func buildRuleArgs(fv domain.FormValues, insertAt int) (string, error) {
	tokens := strings.Fields(strings.ToLower(strings.ReplaceAll(fv.Action, "-", " ")))
	if len(tokens) != 2 {
		return "", fmt.Errorf("invalid action %q", fv.Action)
	}
	verb, dir := tokens[0], tokens[1]

	var args []string
	if dir == "fwd" {
		args = append(args, "route")
	}
	if insertAt > 0 {
		args = append(args, "insert", strconv.Itoa(insertAt))
	}
	args = append(args, verb)

	if dir == "fwd" {
		if fv.Interface != "" {
			args = append(args, "in", "on", utils.ShellArg(fv.Interface))
		}
		if fv.InterfaceOut != "" {
			args = append(args, "out", "on", utils.ShellArg(fv.InterfaceOut))
		}
	} else {
		args = append(args, dir)
		if fv.Interface != "" {
			args = append(args, "on", utils.ShellArg(fv.Interface))
		}
	}

	args = append(args, "from", utils.ShellArg(orAny(fv.From)), "to", utils.ShellArg(orAny(fv.To)))

	if fv.Protocol != "" {
		args = append(args, "proto", utils.ShellArg(fv.Protocol))
	}
	if fv.Port != "" {
		args = append(args, "port", utils.ShellArg(fv.Port))
	}
	if fv.Comment != "" {
		args = append(args, "comment", utils.ShellQuote(fv.Comment))
	}

	return strings.Join(args, " "), nil
}
