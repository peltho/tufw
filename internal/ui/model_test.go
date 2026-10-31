package ui

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/huh/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/peltho/tufw/internal/core/domain"
	"github.com/peltho/tufw/internal/core/service"
)

type fakeFirewall struct {
	rules    []domain.Rule
	active   bool
	deleted  []domain.Rule
	created  []domain.FormValues
	edited   []domain.FormValues
	saveErr  error
	enabled  bool
	disabled bool
}

func (f *fakeFirewall) LoadRules() ([]domain.Rule, error) { return f.rules, nil }
func (f *fakeFirewall) Interfaces() []string              { return []string{"lo", "eth0", "eth1"} }
func (f *fakeFirewall) IsActive() (bool, error)           { return f.active, nil }
func (f *fakeFirewall) Enable() error                     { f.enabled = true; f.active = true; return nil }
func (f *fakeFirewall) Disable() error                    { f.disabled = true; return nil }
func (f *fakeFirewall) Reset() error                      { return nil }
func (f *fakeFirewall) Delete(r domain.Rule) error        { f.deleted = append(f.deleted, r); return nil }
func (f *fakeFirewall) Create(v domain.FormValues) (string, error) {
	f.created = append(f.created, v)
	return "ufw allow ...", f.saveErr
}
func (f *fakeFirewall) Edit(_ domain.Rule, v domain.FormValues) (string, error) {
	f.edited = append(f.edited, v)
	return "ufw insert ...", f.saveErr
}

func sampleRules(n int) []domain.Rule {
	rules := []domain.Rule{
		{Number: 1, Action: "allow", Direction: "in", Protocol: "tcp", DPort: "22", Dst: "0.0.0.0/0", SPort: "any", Src: "192.168.1.0/24", Comment: "SSH from LAN"},
		{Number: 2, Action: "allow", Direction: "in", Protocol: "tcp", DPort: "80,443", Dst: "0.0.0.0/0", SPort: "any", Src: "0.0.0.0/0", DApp: "Apache Full"},
		{Number: 3, Action: "deny", Direction: "out", Protocol: "udp", DPort: "53", Dst: "8.8.8.8", SPort: "any", Src: "0.0.0.0/0", IfaceOut: "eth0", Comment: "Block Google DNS"},
		{Number: 4, Action: "allow", Forward: true, Direction: "in", Protocol: "tcp", DPort: "443", Dst: "172.16.0.5", SPort: "any", Src: "10.0.0.0/8", IfaceIn: "eth1", IfaceOut: "eth0"},
		{Number: 5, Action: "limit", Direction: "in", Protocol: "tcp", DPort: "2222", Dst: "0.0.0.0/0", SPort: "any", Src: "0.0.0.0/0"},
	}
	for i := len(rules); i < n; i++ {
		rules = append(rules, domain.Rule{Number: i + 1, Action: "allow", Direction: "in", Protocol: "tcp", DPort: fmt.Sprint(8000 + i), Dst: "0.0.0.0/0", SPort: "any", Src: "0.0.0.0/0", V6: true})
	}
	return rules[:n]
}

// start returns a sized model with rules loaded.
func start(t *testing.T, fw *fakeFirewall) Model {
	t.Helper()
	m := New(fw, lipgloss.Color("6"))
	m = send(t, m, tea.WindowSizeMsg{Width: 120, Height: 30})
	m = send(t, m, m.loadRules())
	m = send(t, m, m.checkActive())
	return m
}

// send feeds msg to the model and returns the new model.
func send(t *testing.T, m Model, msg tea.Msg) Model {
	t.Helper()
	updated, _ := m.Update(msg)
	return updated.(Model)
}

// sendRun feeds msg and runs the resulting command synchronously, feeding
// its message back (one level, enough for our background operations).
func sendRun(t *testing.T, m Model, msg tea.Msg) (Model, tea.Msg) {
	t.Helper()
	updated, cmd := m.Update(msg)
	m = updated.(Model)
	if cmd == nil {
		return m, nil
	}
	out := cmd()
	if _, isBatch := out.(tea.BatchMsg); isBatch {
		return m, out
	}
	updated, _ = m.Update(out)
	return updated.(Model), out
}

func key(s string) tea.KeyPressMsg {
	switch s {
	case "enter":
		return tea.KeyPressMsg{Code: tea.KeyEnter}
	case "esc":
		return tea.KeyPressMsg{Code: tea.KeyEscape}
	case "down":
		return tea.KeyPressMsg{Code: tea.KeyDown}
	case "up":
		return tea.KeyPressMsg{Code: tea.KeyUp}
	case "end":
		return tea.KeyPressMsg{Code: tea.KeyEnd}
	case "right":
		return tea.KeyPressMsg{Code: tea.KeyRight}
	}
	r := []rune(s)[0]
	return tea.KeyPressMsg{Code: r, Text: s}
}

func typeText(t *testing.T, m Model, s string) Model {
	t.Helper()
	for _, r := range s {
		m = send(t, m, key(string(r)))
	}
	return m
}

func plain(m Model) string { return ansi.Strip(m.render()) }

func TestRendersRules(t *testing.T) {
	m := start(t, &fakeFirewall{rules: sampleRules(5), active: true})
	out := plain(m)

	for _, want := range []string{"tufw", "● active", "5 rules", "SSH from LAN", "Apache Full", "ALLOW-FWD", "LIMIT-IN", "172.16.0.5 on eth0", "a add"} {
		if !strings.Contains(out, want) {
			t.Errorf("view is missing %q:\n%s", want, out)
		}
	}
	if lines := strings.Count(out, "\n") + 1; lines != 30 {
		t.Errorf("view is %d lines high, want 30", lines)
	}
	if os.Getenv("TUFW_PREVIEW") != "" {
		fmt.Println(m.render())
	}
}

func TestInactivePromptsToEnable(t *testing.T) {
	fw := &fakeFirewall{rules: sampleRules(2), active: false}
	m := start(t, fw)
	if m.mode != modeConfirm || !strings.Contains(plain(m), "ufw is disabled") {
		t.Fatalf("expected the enable dialog:\n%s", plain(m))
	}

	m, _ = sendRun(t, m, key("enter")) // Yes is the default here
	if !fw.enabled || m.mode != modeTable {
		t.Errorf("ufw should be enabled, mode %v", m.mode)
	}
}

func TestInactiveDeclineQuits(t *testing.T) {
	m := start(t, &fakeFirewall{rules: sampleRules(2), active: false})
	_, cmd := m.Update(key("n"))
	if cmd == nil {
		t.Fatal("expected quit")
	}
	if _, ok := cmd().(tea.QuitMsg); !ok {
		t.Error("expected tea.QuitMsg")
	}
}

func TestDeleteAsksThenDeletesSelectedRule(t *testing.T) {
	fw := &fakeFirewall{rules: sampleRules(5), active: true}
	m := start(t, fw)
	m = send(t, m, key("down"))
	m = send(t, m, key("down"))
	m = send(t, m, key("d"))

	if m.mode != modeConfirm || !strings.Contains(plain(m), "Delete rule [3]?") {
		t.Fatalf("expected confirmation:\n%s", plain(m))
	}

	// Enter on the default (No) cancels
	m, _ = sendRun(t, m, key("enter"))
	if len(fw.deleted) != 0 || m.mode != modeTable {
		t.Fatalf("nothing should be deleted, got %v", fw.deleted)
	}

	m = send(t, m, key("d"))
	m, _ = sendRun(t, m, key("y"))
	if len(fw.deleted) != 1 || fw.deleted[0].Number != 3 {
		t.Fatalf("expected rule 3 to be deleted, got %+v", fw.deleted)
	}
	if !strings.Contains(plain(m), "Rule [3] deleted") {
		t.Errorf("missing status:\n%s", plain(m))
	}
}

func TestSearchFiltersAndDeleteUsesRealNumber(t *testing.T) {
	fw := &fakeFirewall{rules: sampleRules(5), active: true}
	m := start(t, fw)

	m = send(t, m, key("/"))
	m = typeText(t, m, "dns")
	if len(m.shown) != 1 || m.shown[0].Number != 3 {
		t.Fatalf("filter should match rule 3 only, got %+v", m.shown)
	}
	m = send(t, m, key("enter"))
	if m.mode != modeTable || m.filter != "dns" {
		t.Fatalf("enter should keep the filter, mode %v filter %q", m.mode, m.filter)
	}

	m = send(t, m, key("d"))
	m, _ = sendRun(t, m, key("y"))
	if len(fw.deleted) != 1 || fw.deleted[0].Number != 3 {
		t.Errorf("expected rule 3, got %+v", fw.deleted)
	}

	m = send(t, m, key("esc"))
	if m.filter != "" || len(m.shown) != 5 {
		t.Errorf("esc should clear the filter")
	}
}

func TestEditRefusesUnsupportedRule(t *testing.T) {
	m := start(t, &fakeFirewall{rules: sampleRules(5), active: true})
	m = send(t, m, key("down")) // Apache Full app rule
	m = send(t, m, key("e"))

	if m.mode != modeTable || !m.statusErr || !strings.Contains(m.status, "application profile") {
		t.Errorf("expected an error status, got mode %v status %q", m.mode, m.status)
	}
}

func TestEditOpensPrefilledForm(t *testing.T) {
	m := start(t, &fakeFirewall{rules: sampleRules(5), active: true})
	m = send(t, m, key("down"))
	m = send(t, m, key("down"))
	m = send(t, m, key("e"))

	if m.mode != modeForm {
		t.Fatalf("expected the form, mode %v", m.mode)
	}
	want := domain.FormValues{Action: "DENY OUT", To: "8.8.8.8", Port: "53", Protocol: "udp", Interface: "eth0", Comment: "Block Google DNS"}
	if *m.formData != want {
		t.Errorf("got %+v, want %+v", *m.formData, want)
	}
	out := plain(m)
	for _, s := range []string{"Edit rule [3]", "DENY OUT", "8.8.8.8", "Block Google DNS"} {
		if !strings.Contains(out, s) {
			t.Errorf("form is missing %q:\n%s", s, out)
		}
	}
	if os.Getenv("TUFW_PREVIEW") != "" {
		fmt.Println(m.render())
	}

	m = send(t, m, key("esc"))
	if m.mode != modeTable || m.form != nil {
		t.Error("esc should close the form")
	}
}

func TestSubmitForm(t *testing.T) {
	fw := &fakeFirewall{rules: sampleRules(5), active: true}
	m := start(t, fw)
	m = send(t, m, key("a"))
	m.formData.Port = "8080" // as if typed in
	m.formData.InterfaceOut = "eth1"

	m, _ = sendRun(t, m, ruleSavedMsg{}) // sanity: a save result closes the form
	if m.mode != modeTable {
		t.Fatalf("mode %v", m.mode)
	}

	m = send(t, m, key("a"))
	m.formData.Port = "8080"
	m.formData.InterfaceOut = "eth1" // not a FWD rule: must be dropped
	msg := m.saveRule()()
	if len(fw.created) != 1 || fw.created[0].Port != "8080" || fw.created[0].InterfaceOut != "" || fw.created[0].Action != "ALLOW IN" {
		t.Errorf("unexpected create: %+v", fw.created)
	}
	m = send(t, m, msg)
	if m.mode != modeTable || !strings.Contains(m.status, "ufw allow") {
		t.Errorf("mode %v status %q", m.mode, m.status)
	}
}

func TestInvalidRuleReopensForm(t *testing.T) {
	fw := &fakeFirewall{rules: sampleRules(5), active: true}
	m := start(t, fw)
	m = send(t, m, key("a"))
	m.formData.Port = "99999"

	m = send(t, m, ruleSavedMsg{err: fmt.Errorf("%w: Bad port", service.ErrInvalidRule)})
	if m.mode != modeForm || m.form == nil || m.form.State != huh.StateNormal {
		t.Fatalf("form should be open again, mode %v", m.mode)
	}
	if m.formData.Port != "99999" || !strings.Contains(plain(m), "Bad port") {
		t.Errorf("values and error should be kept:\n%s", plain(m))
	}
}

func TestOtherSaveErrorReturnsToTable(t *testing.T) {
	m := start(t, &fakeFirewall{rules: sampleRules(5), active: true})
	m = send(t, m, key("a"))
	m = send(t, m, ruleSavedMsg{err: errors.New("rule [1] changed since it was loaded")})
	if m.mode != modeTable || !m.statusErr {
		t.Errorf("mode %v statusErr %v", m.mode, m.statusErr)
	}
}

func TestScrolling(t *testing.T) {
	m := start(t, &fakeFirewall{rules: sampleRules(60), active: true})
	rows := m.visibleRows()

	m = send(t, m, key("end"))
	if m.cursor != 59 || m.offset != 60-rows {
		t.Errorf("cursor %d offset %d (rows %d)", m.cursor, m.offset, rows)
	}
	out := plain(m)
	if !strings.Contains(out, "[60]") || strings.Contains(out, "[1] ") {
		t.Errorf("last page should be visible:\n%s", out)
	}
	if !strings.Contains(out, fmt.Sprintf("%d–60 of 60", 60-rows+1)) {
		t.Errorf("missing scroll position:\n%s", out)
	}
	if lines := strings.Count(out, "\n") + 1; lines != 30 {
		t.Errorf("view is %d lines high, want 30", lines)
	}
}

func TestDisableQuits(t *testing.T) {
	fw := &fakeFirewall{rules: sampleRules(2), active: true}
	m := start(t, fw)
	m = send(t, m, key("s"))
	updated, cmd := m.Update(key("y"))
	m = updated.(Model)
	updated, cmd = m.Update(cmd())
	if !fw.disabled || cmd == nil {
		t.Fatal("expected disable then quit")
	}
	if _, ok := cmd().(tea.QuitMsg); !ok {
		t.Error("expected tea.QuitMsg")
	}
}

// drive feeds msg and keeps running the resulting commands, feeding their
// messages back, like the Bubble Tea runtime. Commands that don't return
// quickly (cursor blink ticks) are dropped.
func drive(t *testing.T, m Model, msg tea.Msg) Model {
	t.Helper()
	queue := []tea.Msg{msg}
	for steps := 0; len(queue) > 0 && steps < 500; steps++ {
		next := queue[0]
		queue = queue[1:]
		if batch, ok := next.(tea.BatchMsg); ok {
			for _, c := range batch {
				if out := runQuick(c); out != nil {
					queue = append(queue, out)
				}
			}
			continue
		}
		if _, ok := next.(tea.QuitMsg); ok {
			continue
		}
		updated, cmd := m.Update(next)
		m = updated.(Model)
		if out := runQuick(cmd); out != nil {
			queue = append(queue, out)
		}
	}
	return m
}

func runQuick(cmd tea.Cmd) tea.Msg {
	if cmd == nil {
		return nil
	}
	ch := make(chan tea.Msg, 1)
	go func() { ch <- cmd() }()
	select {
	case msg := <-ch:
		return msg
	case <-time.After(20 * time.Millisecond):
		return nil
	}
}

func TestFormKeyboardFlow(t *testing.T) {
	fw := &fakeFirewall{rules: sampleRules(5), active: true}
	m := start(t, fw)
	m = drive(t, m, key("a"))

	// Action: move to the 2nd option (DENY IN), then through the left column
	m = drive(t, m, key("right"))
	for i := 0; i < 4; i++ { // Action, Interface, Interface out, Comment
		m = drive(t, m, key("enter"))
	}
	m = drive(t, m, key("enter")) // From
	m = drive(t, m, key("enter")) // To
	for _, r := range "8080" {
		m = drive(t, m, key(string(r)))
	}
	m = drive(t, m, key("enter")) // Port
	if len(fw.created) != 0 {
		t.Fatal("form submitted too early")
	}
	m = drive(t, m, key("enter")) // Protocol: submits

	if len(fw.created) != 1 {
		t.Fatalf("expected one created rule, got %+v (mode %v)\n%s", fw.created, m.mode, plain(m))
	}
	if got := fw.created[0]; got.Action != "DENY IN" || got.Port != "8080" {
		t.Errorf("unexpected values %+v", got)
	}
	if m.mode != modeTable {
		t.Errorf("mode %v", m.mode)
	}
}

func TestFormRejectsBadPort(t *testing.T) {
	fw := &fakeFirewall{rules: sampleRules(5), active: true}
	m := start(t, fw)
	m = drive(t, m, key("a"))
	for i := 0; i < 6; i++ {
		m = drive(t, m, key("enter"))
	}
	for _, r := range "abc" {
		m = drive(t, m, key(string(r)))
	}
	m = drive(t, m, key("enter"))
	m = drive(t, m, key("enter"))
	if len(fw.created) != 0 {
		t.Errorf("a bad port must not be submitted: %+v", fw.created)
	}
}
