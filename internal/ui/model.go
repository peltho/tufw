// Package ui is the Bubble Tea terminal interface of tufw.
package ui

import (
	"errors"
	"fmt"
	"image/color"
	"strings"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"charm.land/huh/v2"
	"charm.land/lipgloss/v2"
	"charm.land/lipgloss/v2/table"

	"github.com/peltho/tufw/internal/core/domain"
	"github.com/peltho/tufw/internal/core/service"
	"github.com/peltho/tufw/internal/core/utils"
)

// Firewall is what the UI needs from the service layer.
type Firewall interface {
	LoadRules() ([]domain.Rule, error)
	Interfaces() []string
	IsActive() (bool, error)
	Enable() error
	Disable() error
	Reset() error
	Create(domain.FormValues) (string, error)
	Edit(domain.Rule, domain.FormValues) (string, error)
	Delete(domain.Rule) error
}

type mode int

const (
	modeTable mode = iota
	modeSearch
	modeForm
	modeConfirm
)

// Table columns.
const (
	colIndex = iota
	colTo
	colPort
	colProto
	colAction
	colFrom
	colComment
)

var columns = []string{"#", "To", "Port", "Proto", "Action", "From", "Comment"}

// Fixed layout: header line + blank line, status line, footer line.
const (
	headerHeight = 2
	statusHeight = 1
	footerHeight = 1
	// rounded border top + header row + header separator + border bottom
	tableChrome = 4
)

type (
	rulesLoadedMsg struct {
		rules []domain.Rule
		err   error
	}
	activeCheckedMsg struct {
		active bool
		err    error
	}
	opDoneMsg struct {
		status  string
		err     error
		quit    bool // quit tufw on success
		recheck bool // check whether ufw is active again
	}
	ruleSavedMsg struct {
		cmd string
		err error
	}
)

type confirmDialog struct {
	title string
	body  string
	yes   bool    // highlighted button
	onYes tea.Cmd // runs as a busy operation
	onNo  tea.Cmd
}

type Model struct {
	fw     Firewall
	st     styles
	width  int
	height int

	rules  []domain.Rule // all rules
	shown  []domain.Rule // rules matching the filter
	cursor int           // index in shown
	offset int           // first visible row
	active bool

	mode   mode
	search textinput.Model
	filter string

	form     *huh.Form
	formData *domain.FormValues // bound to the form fields
	formErr  string
	editing  *domain.Rule // nil when adding

	confirm confirmDialog

	status    string
	statusErr bool
	busy      bool
}

func New(fw Firewall, accent color.Color) Model {
	search := textinput.New()
	search.Prompt = "/ "
	search.Placeholder = "regex, e.g. 22|ssh"

	return Model{
		fw:     fw,
		st:     newStyles(accent),
		search: search,
		active: true,
	}
}

func (m Model) Init() tea.Cmd {
	return tea.Batch(m.loadRules, m.checkActive)
}

func (m Model) loadRules() tea.Msg {
	rules, err := m.fw.LoadRules()
	return rulesLoadedMsg{rules: rules, err: err}
}

func (m Model) checkActive() tea.Msg {
	active, err := m.fw.IsActive()
	return activeCheckedMsg{active: active, err: err}
}

// op runs f in the background and reports the outcome.
func (m Model) op(f func() error, success string, quit, recheck bool) tea.Cmd {
	return func() tea.Msg {
		return opDoneMsg{status: success, err: f(), quit: quit, recheck: recheck}
	}
}

func (m *Model) setStatus(s string) { m.status, m.statusErr = s, false }
func (m *Model) setError(err error) { m.status, m.statusErr = err.Error(), true }

func (m *Model) applyFilter() {
	m.shown = service.FilterRules(m.rules, m.filter)
}

func (m Model) selected() (domain.Rule, bool) {
	if m.cursor < 0 || m.cursor >= len(m.shown) {
		return domain.Rule{}, false
	}
	return m.shown[m.cursor], true
}

func (m Model) bodyHeight() int {
	return max(m.height-headerHeight-statusHeight-footerHeight, 0)
}

// visibleRows is how many rules fit in the table.
func (m Model) visibleRows() int {
	h := m.bodyHeight() - tableChrome
	if m.mode == modeSearch || m.filter != "" {
		h-- // search / filter line
	}
	return max(h, 1)
}

// clampCursor keeps the cursor on a rule and scrolls it into view.
func (m *Model) clampCursor() {
	n := len(m.shown)
	m.cursor = min(max(m.cursor, 0), max(n-1, 0))

	rows := m.visibleRows()
	if m.cursor < m.offset {
		m.offset = m.cursor
	}
	if m.cursor >= m.offset+rows {
		m.offset = m.cursor - rows + 1
	}
	m.offset = min(max(m.offset, 0), max(n-rows, 0))
}

func (m *Model) ask(title, body string, defaultYes bool, onYes, onNo tea.Cmd) {
	m.confirm = confirmDialog{title: title, body: body, yes: defaultYes, onYes: onYes, onNo: onNo}
	m.mode = modeConfirm
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	m, cmd := m.update(msg)
	m.clampCursor()
	return m, cmd
}

func (m Model) update(msg tea.Msg) (Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.search.SetWidth(max(m.width-4, 10))
		if m.form != nil {
			m.form = m.form.WithWidth(m.formWidth()).WithHeight(m.formHeight())
		}
		return m, nil

	case tea.KeyPressMsg:
		if msg.String() == "ctrl+c" {
			return m, tea.Quit
		}

	case rulesLoadedMsg:
		if msg.err != nil {
			m.setError(msg.err)
		} else {
			m.rules = msg.rules
			m.applyFilter()
		}
		return m, nil

	case activeCheckedMsg:
		if msg.err != nil {
			m.setError(msg.err)
			return m, nil
		}
		m.active = msg.active
		if !msg.active {
			m.ask("ufw is disabled",
				"The firewall is not filtering any traffic.\nEnable it now? Choosing No quits tufw.",
				true, m.op(m.fw.Enable, "ufw enabled", false, true), tea.Quit)
		}
		return m, nil

	case opDoneMsg:
		m.busy = false
		if msg.err != nil {
			m.setError(msg.err)
		} else {
			m.setStatus(msg.status)
			if msg.quit {
				return m, tea.Quit
			}
		}
		cmds := []tea.Cmd{m.loadRules}
		if msg.recheck {
			cmds = append(cmds, m.checkActive)
		}
		return m, tea.Batch(cmds...)

	case ruleSavedMsg:
		m.busy = false
		if msg.err != nil {
			// The rule was refused before anything changed: let the user fix it.
			if errors.Is(msg.err, service.ErrInvalidRule) || errors.Is(msg.err, service.ErrEmptyRule) {
				m.formErr = msg.err.Error()
				return m, m.openForm()
			}
			m.mode, m.form = modeTable, nil
			m.setError(msg.err)
			return m, m.loadRules
		}
		m.mode, m.form = modeTable, nil
		m.setStatus(msg.cmd)
		return m, m.loadRules
	}

	if m.busy {
		return m, nil
	}

	switch m.mode {
	case modeForm:
		return m.updateForm(msg)
	case modeConfirm:
		return m.updateConfirm(msg)
	case modeSearch:
		return m.updateSearch(msg)
	default:
		return m.updateTable(msg)
	}
}

func (m Model) updateTable(msg tea.Msg) (Model, tea.Cmd) {
	key, ok := msg.(tea.KeyPressMsg)
	if !ok {
		return m, nil
	}

	switch key.String() {
	case "q":
		return m, tea.Quit
	case "up", "k":
		m.cursor--
	case "down", "j":
		m.cursor++
	case "pgup", "ctrl+b":
		m.cursor -= m.visibleRows()
	case "pgdown", "ctrl+f":
		m.cursor += m.visibleRows()
	case "home", "g":
		m.cursor = 0
	case "end", "G":
		m.cursor = len(m.shown) - 1

	case "/":
		m.mode = modeSearch
		m.search.SetValue(m.filter)
		m.search.CursorEnd()
		return m, m.search.Focus()
	case "esc":
		m.filter = ""
		m.applyFilter()
	case "r":
		m.setStatus("Rules reloaded")
		return m, m.loadRules

	case "a":
		m.editing = nil
		m.formData = &domain.FormValues{Action: service.ActionOptions[0]}
		m.formErr = ""
		return m, m.openForm()

	case "e", "enter":
		rule, ok := m.selected()
		if !ok {
			break
		}
		values, err := service.RuleToFormValues(rule)
		if err != nil {
			m.setError(err)
			break
		}
		m.editing = &rule
		m.formData = &values
		m.formErr = ""
		return m, m.openForm()

	case "d", "x", "delete":
		rule, ok := m.selected()
		if !ok {
			break
		}
		m.ask(fmt.Sprintf("Delete rule [%d]?", rule.Number), describeRule(rule), false,
			m.op(func() error { return m.fw.Delete(rule) }, fmt.Sprintf("Rule [%d] deleted", rule.Number), false, false), nil)

	case "s":
		m.ask("Disable ufw?", "The firewall stops filtering traffic.\ntufw exits afterwards.", false,
			m.op(m.fw.Disable, "ufw disabled", true, false), nil)

	case "R":
		m.ask("Reset all rules?", "ufw is disabled and every rule is deleted\n(ufw keeps a backup). tufw exits afterwards.", false,
			m.op(m.fw.Reset, "Rules reset", true, false), nil)
	}

	return m, nil
}

func (m Model) updateSearch(msg tea.Msg) (Model, tea.Cmd) {
	if key, ok := msg.(tea.KeyPressMsg); ok {
		switch key.String() {
		case "enter", "down", "up":
			m.mode = modeTable
			m.search.Blur()
			return m, nil
		case "esc":
			m.mode = modeTable
			m.search.Blur()
			m.search.SetValue("")
			m.filter = ""
			m.applyFilter()
			return m, nil
		}
	}

	var cmd tea.Cmd
	m.search, cmd = m.search.Update(msg)
	if m.search.Value() != m.filter {
		m.filter = m.search.Value()
		m.applyFilter()
		m.cursor = 0
	}
	return m, cmd
}

func (m Model) updateConfirm(msg tea.Msg) (Model, tea.Cmd) {
	key, ok := msg.(tea.KeyPressMsg)
	if !ok {
		return m, nil
	}

	switch key.String() {
	case "y", "Y":
		return m.resolveConfirm(true)
	case "n", "N", "esc":
		return m.resolveConfirm(false)
	case "left", "right", "h", "l", "tab", "shift+tab":
		m.confirm.yes = !m.confirm.yes
	case "enter":
		return m.resolveConfirm(m.confirm.yes)
	}
	return m, nil
}

func (m Model) resolveConfirm(yes bool) (Model, tea.Cmd) {
	m.mode = modeTable
	if yes && m.confirm.onYes != nil {
		m.busy = true
		return m, m.confirm.onYes
	}
	if !yes {
		return m, m.confirm.onNo
	}
	return m, nil
}

func (m Model) updateForm(msg tea.Msg) (Model, tea.Cmd) {
	if key, ok := msg.(tea.KeyPressMsg); ok && key.String() == "esc" {
		m.mode, m.form = modeTable, nil
		return m, nil
	}

	updated, cmd := m.form.Update(msg)
	if f, ok := updated.(*huh.Form); ok {
		m.form = f
	}

	switch m.form.State {
	case huh.StateCompleted:
		m.busy = true
		return m, m.saveRule()
	case huh.StateAborted:
		m.mode, m.form = modeTable, nil
		return m, nil
	}
	return m, cmd
}

func (m Model) saveRule() tea.Cmd {
	values := *m.formData
	if !service.IsForwardAction(values.Action) {
		values.InterfaceOut = ""
	}
	editing := m.editing
	fw := m.fw

	return func() tea.Msg {
		if editing != nil {
			cmd, err := fw.Edit(*editing, values)
			return ruleSavedMsg{cmd: cmd, err: err}
		}
		cmd, err := fw.Create(values)
		return ruleSavedMsg{cmd: cmd, err: err}
	}
}

// describeRule is a one-line summary for dialogs.
func describeRule(r domain.Rule) string {
	c := utils.RuleCells(r)
	port := c.Port
	if c.Proto != "-" {
		port += "/" + c.Proto
	}
	s := fmt.Sprintf("%s  %s → %s  port %s", c.Action, c.From, c.To, port)
	if c.Comment != "" {
		s += "\n# " + c.Comment
	}
	return s
}

// ---------------------------------------------------------------- view

func (m Model) View() tea.View {
	v := tea.NewView(m.render())
	v.AltScreen = true
	v.WindowTitle = "tufw"
	return v
}

func (m Model) render() string {
	if m.width == 0 || m.height == 0 {
		return "Loading…"
	}

	h := m.bodyHeight()
	var body string
	switch m.mode {
	case modeForm:
		body = m.formView(h)
	case modeConfirm:
		body = lipgloss.Place(m.width, h, lipgloss.Center, lipgloss.Center, m.confirmView())
	default:
		body = m.tableView(h)
	}
	body = lipgloss.NewStyle().Height(h).MaxHeight(h).Render(body)

	return lipgloss.JoinVertical(lipgloss.Left, m.headerView(), body, m.statusView(), m.footerView())
}

func (m Model) headerView() string {
	state := m.st.active.Render("● active")
	if !m.active {
		state = m.st.inactive.Render("● inactive")
	}
	left := m.st.badge.Render("tufw") + "  " + state

	right := fmt.Sprintf("%d rules", len(m.rules))
	if n := len(m.shown); n > m.visibleRows() && m.mode != modeForm {
		right = fmt.Sprintf("%d–%d of %d", m.offset+1, min(m.offset+m.visibleRows(), n), n)
		if m.filter != "" {
			right += fmt.Sprintf(" (filtered from %d)", len(m.rules))
		}
	}
	right = m.st.muted.Render(right)

	gap := max(m.width-lipgloss.Width(left)-lipgloss.Width(right)-2, 1)
	return " " + left + strings.Repeat(" ", gap) + right + "\n"
}

func (m Model) tableView(height int) string {
	var top string
	switch {
	case m.mode == modeSearch:
		top = " " + m.search.View()
	case m.filter != "":
		top = m.st.muted.Render(fmt.Sprintf(" filter /%s/ · %d of %d rules · esc to clear", m.filter, len(m.shown), len(m.rules)))
	}

	var tbl string
	if len(m.shown) == 0 {
		msg := "No rules yet. Press a to add one."
		if m.filter != "" {
			msg = "No rule matches /" + m.filter + "/"
		}
		h := height
		if top != "" {
			h--
		}
		tbl = lipgloss.Place(m.width, h, lipgloss.Center, lipgloss.Center, m.st.empty.Render(msg))
	} else {
		tbl = m.renderTable()
	}

	if top == "" {
		return tbl
	}
	return lipgloss.JoinVertical(lipgloss.Left, top, tbl)
}

func (m Model) renderTable() string {
	end := min(m.offset+m.visibleRows(), len(m.shown))
	page := m.shown[m.offset:end]

	rows := make([][]string, len(page))
	for i, r := range page {
		c := utils.RuleCells(r)
		rows[i] = []string{c.Index, c.To, c.Port, c.Proto, c.Action, c.From, c.Comment}
	}

	t := table.New().
		Border(lipgloss.RoundedBorder()).
		BorderStyle(m.st.border).
		BorderColumn(false).
		Headers(columns...).
		Rows(rows...).
		Wrap(false).
		StyleFunc(func(row, col int) lipgloss.Style {
			if row == table.HeaderRow {
				return m.st.header
			}
			return m.st.cellStyle(col, rows[row][col], m.offset+row == m.cursor)
		})

	// Columns fit their content; only squeeze them on narrow terminals.
	out := t.Render()
	if lipgloss.Width(out) > m.width {
		out = t.Width(m.width).Render()
	}
	return out
}

func (m Model) confirmView() string {
	yes, no := m.st.button.Render("Yes"), m.st.button.Render("No")
	if m.confirm.yes {
		yes = m.st.buttonOn.Render("Yes")
	} else {
		no = m.st.buttonOn.Render("No")
	}
	content := lipgloss.JoinVertical(lipgloss.Left,
		m.st.dlgTitle.Render(m.confirm.title),
		"",
		m.confirm.body,
		"",
		yes+"  "+no,
	)
	return m.st.dialog.Render(content)
}

func (m Model) statusView() string {
	var s string
	switch {
	case m.busy:
		s = m.st.statusRun.Render("… applying")
	case m.status == "":
		return ""
	case m.statusErr:
		s = m.st.statusErr.Render("✗ " + m.status)
	default:
		s = m.st.statusOK.Render("✓ " + m.status)
	}
	return lipgloss.NewStyle().MaxWidth(m.width).Render(" " + s)
}

type hint struct{ key, desc string }

func (m Model) footerView() string {
	var hints []hint
	switch m.mode {
	case modeSearch:
		hints = []hint{{"enter", "keep filter"}, {"esc", "clear"}}
	case modeForm:
		hints = []hint{{"tab/enter", "next"}, {"shift+tab", "back"}, {"←/→", "change option"}, {"enter on Protocol", "save"}, {"esc", "cancel"}}
	case modeConfirm:
		hints = []hint{{"←/→", "choose"}, {"enter", "confirm"}, {"y/n", "yes/no"}, {"esc", "cancel"}}
	default:
		hints = []hint{{"a", "add"}, {"e", "edit"}, {"d", "delete"}, {"/", "search"}, {"r", "reload"}, {"s", "disable"}, {"R", "reset"}, {"q", "quit"}}
	}

	parts := make([]string, len(hints))
	for i, h := range hints {
		parts[i] = m.st.key.Render(h.key) + " " + m.st.keyDesc.Render(h.desc)
	}
	sep := m.st.muted.Render(" · ")
	return lipgloss.NewStyle().MaxWidth(m.width).Render(" " + strings.Join(parts, sep))
}
