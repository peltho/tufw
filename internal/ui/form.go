package ui

import (
	"errors"
	"fmt"
	"regexp"
	"slices"

	tea "charm.land/bubbletea/v2"
	"charm.land/huh/v2"
	"charm.land/lipgloss/v2"

	"github.com/peltho/tufw/internal/core/service"
)

const maxFormWidth = 84

var portPattern = regexp.MustCompile(`^[0-9]+([:,][0-9]+)*$`)

func validatePort(s string) error {
	if s == "" || portPattern.MatchString(s) {
		return nil
	}
	return errors.New("use a port (22), a list (80,443) or a range (6000:6007)")
}

func (m Model) formWidth() int {
	return max(min(m.width-6, maxFormWidth), 20)
}

func (m Model) formHeight() int {
	h := m.bodyHeight() - 2 - 3 // box border, title + description + blank line
	if m.formErr != "" {
		h -= 2
	}
	return max(h, 5)
}

// openForm shows the add/edit form, bound to m.formData.
func (m *Model) openForm() tea.Cmd {
	m.mode = modeForm
	m.form = m.buildForm()
	return m.form.Init()
}

func anyOption(label string) huh.Option[string] {
	return huh.NewOption(label, "")
}

func (m Model) buildForm() *huh.Form {
	d := m.formData

	ifaces := m.fw.Interfaces()
	// Keep interfaces referenced by the rule even if they are currently down.
	for _, name := range []string{d.Interface, d.InterfaceOut} {
		if name != "" && !slices.Contains(ifaces, name) {
			ifaces = append(ifaces, name)
		}
	}
	ifaceOptions := []huh.Option[string]{anyOption("any")}
	for _, name := range ifaces {
		ifaceOptions = append(ifaceOptions, huh.NewOption(name, name))
	}

	// Two columns: what the rule does, and what traffic it matches.
	ruleGroup := huh.NewGroup(
		huh.NewSelect[string]().
			Title("Action").
			Options(huh.NewOptions(service.ActionOptions...)...).
			Value(&d.Action).
			Inline(true),
		huh.NewSelect[string]().
			Title("Interface").
			Options(ifaceOptions...).
			Value(&d.Interface).
			Inline(true),
		huh.NewSelect[string]().
			Title("Interface out").
			Description("FWD rules only").
			Options(ifaceOptions...).
			Value(&d.InterfaceOut).
			Inline(true).
			Validate(func(v string) error {
				switch {
				case v == "":
					return nil
				case !service.IsForwardAction(d.Action):
					return errors.New("only for FWD rules")
				case v == d.Interface:
					return errors.New("must differ from Interface")
				}
				return nil
			}),
		huh.NewInput().
			Title("Comment").
			Placeholder("optional").
			Value(&d.Comment),
	)

	matchGroup := huh.NewGroup(
		huh.NewInput().
			Title("From").
			Placeholder("any").
			Value(&d.From),
		huh.NewInput().
			Title("To").
			Placeholder("any").
			Value(&d.To),
		huh.NewInput().
			Title("Port").
			Placeholder("any · 22 · 80,443 · 6000:6007").
			Value(&d.Port).
			Validate(validatePort),
		huh.NewSelect[string]().
			Title("Protocol").
			Options(anyOption("any"), huh.NewOption("tcp", "tcp"), huh.NewOption("udp", "udp")).
			Value(&d.Protocol).
			Inline(true),
	)

	return huh.NewForm(ruleGroup, matchGroup).
		WithLayout(huh.LayoutColumns(2)).
		WithTheme(m.st.formTheme).
		WithWidth(m.formWidth()).
		WithHeight(m.formHeight()).
		WithShowHelp(false)
}

func (m Model) formTitle() string {
	if m.editing != nil {
		return fmt.Sprintf("Edit rule [%d]", m.editing.Number)
	}
	return "Add a rule"
}

func (m Model) formView(height int) string {
	parts := []string{
		m.st.dlgTitle.Render(m.formTitle()),
		m.st.muted.Render("Empty fields match anything."),
	}
	if m.formErr != "" {
		parts = append(parts, "", m.st.formErr.Render("✗ "+m.formErr))
	}
	parts = append(parts, "", m.form.View())
	content := lipgloss.JoinVertical(lipgloss.Left, parts...)
	return lipgloss.Place(m.width, height, lipgloss.Center, lipgloss.Center, m.st.formBox.Render(content))
}
