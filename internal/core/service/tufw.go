package service

import (
	"errors"
	"fmt"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/peltho/tufw/internal/core/domain"
	"github.com/peltho/tufw/internal/core/utils"
	"github.com/rivo/tview"
)

var (
	// Overridable in tests.
	shellout = utils.Shellout
	readFile = os.ReadFile

	// ufw >= 0.34 keeps user rules in /etc/ufw, older releases in /lib/ufw.
	rulesFileLocations = [][2]string{
		{"/etc/ufw/user.rules", "/etc/ufw/user6.rules"},
		{"/lib/ufw/user.rules", "/lib/ufw/user6.rules"},
	}
	ufwDefaultsFile = "/etc/default/ufw"
)

var (
	actionOptions   = []string{"ALLOW IN", "DENY IN", "REJECT IN", "LIMIT IN", "ALLOW OUT", "DENY OUT", "REJECT OUT", "LIMIT OUT", "ALLOW FWD", "DENY FWD"}
	protocolOptions = []string{"", "tcp", "udp"}
)

type Tui struct {
	app        *tview.Application
	form       *tview.Form
	table      *tview.Table
	menu       *tview.Flex
	help       *tview.TextView
	secondHelp *tview.TextView
	pages      *tview.Pages
	color      tcell.Color

	rules     []domain.Rule // all rules, as last loaded
	displayed []domain.Rule // rules currently shown, one per table row (after the header)
}

func CreateApplication(color tcell.Color) *Tui {
	tui := Tui{color: color}
	return &tui
}

func (t *Tui) Init() {
	t.app = tview.NewApplication()
	t.table = tview.NewTable()
	t.form = tview.NewForm()
	t.menu = tview.NewFlex()
	t.help = tview.NewTextView()
	t.secondHelp = tview.NewTextView()
	t.pages = tview.NewPages()
}

func (t *Tui) LoadInterfaces() ([]string, error) {
	out, _, err := shellout("ip link show | awk -F: '{ print $2 }' | sed -r 's/^[0-9]+//' | sed '/^$/d' | awk '{$2=$2};1'")
	if err != nil {
		log.Printf("error: %v\n", err)
	}

	interfaces := []string{""}
	interfaces = append(interfaces, strings.Fields(out)...)

	return interfaces, nil
}

// LoadRules reads the rules ufw stores in user.rules and user6.rules and
// numbers them the way `ufw status numbered` does.
func (t *Tui) LoadRules() ([]domain.Rule, error) {
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

// checkRuleNumber must pass before any command addressing a rule by number
// (delete, insert). It reloads the rules, checks that our numbering agrees
// with ufw's own (`ufw status numbered`) and that the rule at that number is
// still the one the user selected.
func (t *Tui) checkRuleNumber(selected domain.Rule) error {
	rules, err := t.LoadRules()
	if err != nil {
		return err
	}

	out, trace, err := shellout("ufw status numbered")
	if err != nil {
		return fmt.Errorf("ufw status numbered failed: %s", strings.TrimSpace(trace))
	}
	if strings.Contains(out, "Status: inactive") {
		return errors.New("ufw is inactive, rule numbers cannot be verified")
	}
	if n := utils.CountNumberedRules(out); n != len(rules) {
		return fmt.Errorf("ufw lists %d rules but the rule files contain %d, refusing to modify rules by number", n, len(rules))
	}
	if selected.Number < 1 || selected.Number > len(rules) || rules[selected.Number-1] != selected {
		return fmt.Errorf("rule [%d] changed since the table was loaded, reload and try again", selected.Number)
	}

	t.rules = rules
	return nil
}

func (t *Tui) showError(err error) {
	log.Print(err)
	t.secondHelp.SetText(" "+err.Error()).SetTextColor(tcell.ColorRed).SetBorderPadding(0, 0, 1, 1)
}

func (t *Tui) LoadSearchData(needle string) ([]domain.Rule, error) {
	re, err := regexp.Compile("(?i)" + needle)
	if err != nil {
		return nil, fmt.Errorf("invalid search pattern: %w", err)
	}

	var matches []domain.Rule
	for _, rule := range t.rules {
		if re.MatchString(utils.RuleSearchText(rule)) {
			matches = append(matches, rule)
		}
	}

	return matches, nil
}

func (t *Tui) CreateTable(rules []domain.Rule) {
	t.displayed = rules
	t.table.SetFixed(1, 1).SetBorderPadding(1, 0, 1, 1)

	columns := []string{"#", "To", "Port", "Proto", "Action", "From", "Comment"}
	for c, name := range columns {
		t.table.SetCell(0, c, tview.NewTableCell(name).SetTextColor(t.color).SetAlign(tview.AlignCenter))
	}

	for r, rule := range rules {
		cv := utils.RuleCells(rule)
		values := []string{cv.Index, cv.To, cv.Port, cv.Proto, cv.Action, cv.From, cv.Comment}
		for c, value := range values {
			alignment := tview.AlignCenter
			if c == len(values)-1 {
				alignment = tview.AlignLeft
			}
			t.table.SetCell(r+1, c,
				tview.NewTableCell(value).
					SetTextColor(tcell.ColorWhite).
					SetAlign(alignment).
					SetExpansion(1),
			)
		}
	}

	t.table.SetBorder(true).SetTitle(" Status ")
	t.table.SetBorders(false).SetSeparator(tview.Borders.Vertical)

	t.table.SetFocusFunc(func() {
		t.table.SetSelectable(true, false)
	})

	t.table.Select(1, 0).SetFixed(1, 1).SetDoneFunc(func(key tcell.Key) {
		if key == tcell.KeyEscape {
			t.table.SetSelectable(false, false)
			t.help.Clear()
			t.app.SetFocus(t.menu)
		}
	})
}

func (t *Tui) ReloadTable() {
	t.table.Clear()
	rules, err := t.LoadRules()
	if err != nil {
		t.showError(err)
	}
	t.rules = rules
	t.CreateTable(rules)
}

// selectedRule returns the rule displayed at a table row.
func (t *Tui) selectedRule(row int) (domain.Rule, bool) {
	if row < 1 || row > len(t.displayed) {
		return domain.Rule{}, false
	}
	return t.displayed[row-1], true
}

func (t *Tui) CreateModal(text string, confirm func(), cancel func(), finally func()) {
	modal := tview.NewModal()
	t.pages.AddPage("modal", modal.SetText(text).AddButtons([]string{"Confirm", "Cancel"}).SetDoneFunc(func(i int, label string) {
		if label == "Confirm" {
			confirm()
			t.ReloadTable()
		} else {
			cancel()
		}
		modal.ClearButtons()
		finally()
	}), true, true)
}

func (t *Tui) SearchForm() {
	t.form.AddInputField("Regex", "", 20, nil, nil).SetFieldTextColor(tcell.ColorWhite).AddButton("Search", func() {
		needle := t.form.GetFormItem(0).(*tview.InputField).GetText()
		data, err := t.LoadSearchData(needle)
		if err != nil {
			t.showError(err)
			return
		}

		if len(data) > 0 {
			t.table.Clear()
			t.CreateTable(data)
		} else {
			t.secondHelp.SetText(" No result.")
		}
	}).AddButton("Cancel", func() {
		t.Reset()
		t.ReloadTable()
		t.app.SetFocus(t.menu)
	})
}

// updateInterfaces removes selectedIn from the list, always keeping the
// empty "no interface" option.
func updateInterfaces(interfaces []string, selectedIn string) []string {
	var filtered []string
	for _, iface := range interfaces {
		if iface == "" || iface != selectedIn {
			filtered = append(filtered, iface)
		}
	}

	return filtered
}

func isForwardAction(action string) bool {
	return strings.HasSuffix(strings.ToUpper(action), "FWD")
}

// buildRuleForm fills t.form with the rule fields, prefilled with v.
func (t *Tui) buildRuleForm(v domain.FormValues, onSave, onCancel func()) {
	t.form.Clear(true)
	t.help.SetText("Use <Tab> and <Enter> keys to navigate through the form").SetBorderPadding(1, 0, 1, 1)
	interfaces, _ := t.LoadInterfaces()

	inIdx := utils.ParseInterfaceIndex(v.Interface, interfaces)
	outOptions := updateInterfaces(interfaces, interfaces[inIdx])

	ifaceOutDropDown := tview.NewDropDown().
		SetLabel("Interface out").
		SetOptions(outOptions, nil).
		SetCurrentOption(utils.ParseInterfaceIndex(v.InterfaceOut, outOptions))

	ifaceInDropDown := tview.NewDropDown().
		SetLabel("Interface").
		SetOptions(interfaces, nil).
		SetCurrentOption(inIdx)

	// Interface out can't be the same as Interface
	ifaceInDropDown.SetSelectedFunc(func(text string, _ int) {
		_, current := ifaceOutDropDown.GetCurrentOption()
		options := updateInterfaces(interfaces, text)
		ifaceOutDropDown.SetOptions(options, nil).SetCurrentOption(utils.ParseInterfaceIndex(current, options))
	})

	actionIdx := 0
	for i, a := range actionOptions {
		if a == strings.ToUpper(strings.ReplaceAll(v.Action, "-", " ")) {
			actionIdx = i
		}
	}

	t.form.AddInputField("To", v.To, 20, nil, nil).SetFieldTextColor(tcell.ColorWhite).
		AddInputField("Port", v.Port, 20, utils.ValidatePort, nil).SetFieldTextColor(tcell.ColorWhite).
		AddDropDown("Action *", actionOptions, actionIdx, nil).
		AddFormItem(ifaceInDropDown).
		AddDropDown("Protocol", protocolOptions, utils.ParseInterfaceIndex(v.Protocol, protocolOptions), nil).
		AddInputField("From", v.From, 20, nil, nil).
		AddInputField("Comment", v.Comment, 40, nil, nil)

	// Interface out only applies to route (FWD) rules
	showInterfaceOut := func(action string) {
		idx := t.form.GetFormItemIndex("Interface out")
		if isForwardAction(action) && idx == -1 {
			t.form.AddFormItem(ifaceOutDropDown)
		} else if !isForwardAction(action) && idx != -1 {
			t.form.RemoveFormItem(idx)
		}
	}
	showInterfaceOut(actionOptions[actionIdx])
	// Set after construction: AddDropDown fires its callback immediately.
	t.form.GetFormItemByLabel("Action *").(*tview.DropDown).SetSelectedFunc(func(action string, _ int) {
		showInterfaceOut(action)
	})

	t.form.AddButton("Save", onSave).
		AddButton("Cancel", onCancel).
		SetButtonTextColor(tcell.ColorWhite).
		SetButtonBackgroundColor(t.color).
		SetFieldBackgroundColor(t.color).
		SetLabelColor(tcell.ColorWhite)

	t.secondHelp.SetText("* Mandatory field\n\nPort, To and From fields respectively match any and Anywhere if left empty").
		SetTextColor(t.color).
		SetBorderPadding(0, 0, 1, 1)
}

func (t *Tui) CreateForm() {
	t.buildRuleForm(domain.FormValues{}, func() { t.CreateRule() }, func() {
		t.Reset()
		t.app.SetFocus(t.menu)
	})
}

func (t *Tui) ParseFormValues() domain.FormValues {
	var fv domain.FormValues

	for i := 0; i < t.form.GetFormItemCount(); i++ {
		item := t.form.GetFormItem(i)
		label := strings.TrimSpace(item.GetLabel())

		text := ""
		switch f := item.(type) {
		case *tview.InputField:
			text = f.GetText()
		case *tview.DropDown:
			_, text = f.GetCurrentOption()
		}

		switch label {
		case "To":
			fv.To = text
		case "Port":
			fv.Port = text
		case "Action *":
			fv.Action = strings.ToLower(strings.ReplaceAll(text, " ", "-"))
		case "Interface":
			fv.Interface = text
		case "Interface out":
			fv.InterfaceOut = text
		case "Protocol":
			fv.Protocol = text
		case "From":
			fv.From = text
		case "Comment":
			fv.Comment = text
		}
	}

	return fv
}

// ruleToFormValues converts a rule into form values, or explains why the
// form can't represent it (editing it would silently drop parts of the rule).
func ruleToFormValues(r domain.Rule) (domain.FormValues, error) {
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
	for _, a := range actionOptions {
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

func (t *Tui) EditForm() {
	t.table.SetSelectedFunc(func(row int, column int) {
		rule, ok := t.selectedRule(row)
		if !ok {
			t.app.SetFocus(t.table)
			return
		}

		values, err := ruleToFormValues(rule)
		if err != nil {
			t.showError(err)
			return
		}

		t.buildRuleForm(values, func() {
			t.EditRule(rule, t.ParseFormValues())
			t.app.SetFocus(t.table)
		}, func() {
			t.Reset()
			t.help.SetText("Press <Esc> to go back to the menu selection").SetBorderPadding(1, 0, 1, 0)
			t.app.SetFocus(t.table)
		})

		t.app.SetFocus(t.form)
	})
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

// EditRule replaces rule with the given values, keeping its position.
// Returns the ufw command that was applied, nil if nothing was done.
func (t *Tui) EditRule(rule domain.Rule, object domain.FormValues) *string {
	if isEmptyRule(object) {
		return nil
	}

	if err := t.checkRuleNumber(rule); err != nil {
		t.showError(err)
		return nil
	}

	// After deleting the last rule there is nothing left to insert before.
	insertAt := 0
	if rule.Number < len(t.rules) {
		insertAt = rule.Number
	}

	args, err := buildRuleArgs(object, insertAt)
	if err != nil {
		t.showError(err)
		return nil
	}
	baseCmd := "ufw " + args

	// Validate the new rule before touching the old one
	if _, trace, err := shellout("ufw --dry-run " + args); err != nil {
		t.showError(fmt.Errorf("invalid rule: %s (%s)", strings.TrimSpace(trace), baseCmd))
		return nil
	}

	if _, trace, err := shellout(fmt.Sprintf("ufw --force delete %d", rule.Number)); err != nil {
		t.showError(fmt.Errorf("failed to delete rule [%d]: %s", rule.Number, strings.TrimSpace(trace)))
		return nil
	}

	if _, trace, err := shellout(baseCmd); err != nil {
		t.showError(fmt.Errorf("rule [%d] was deleted but the replacement failed: %s (%s)", rule.Number, strings.TrimSpace(trace), baseCmd))
		t.ReloadTable()
		return nil
	}
	log.Printf("Editing rule: %s", baseCmd)

	t.Reset()
	t.ReloadTable()
	return &baseCmd
}

// CreateRule appends the rule described by the form.
// Returns the ufw command that was applied, nil if nothing was done.
func (t *Tui) CreateRule() *string {
	fv := t.ParseFormValues()
	if isEmptyRule(fv) {
		return nil
	}

	args, err := buildRuleArgs(fv, 0)
	if err != nil {
		t.showError(err)
		return nil
	}
	baseCmd := "ufw " + args

	if _, trace, err := shellout("ufw --dry-run " + args); err != nil {
		t.showError(fmt.Errorf("invalid rule: %s (%s)", strings.TrimSpace(trace), baseCmd))
		return nil
	}
	if _, trace, err := shellout(baseCmd); err != nil {
		t.showError(fmt.Errorf("failed to apply rule: %s (%s)", strings.TrimSpace(trace), baseCmd))
		return nil
	}
	log.Printf("Creating rule: %s", baseCmd)

	t.Reset()
	t.ReloadTable()
	return &baseCmd
}

// DeleteRule removes rule after checking its number is still accurate.
func (t *Tui) DeleteRule(rule domain.Rule) error {
	if err := t.checkRuleNumber(rule); err != nil {
		return err
	}
	if _, trace, err := shellout(fmt.Sprintf("ufw --force delete %d", rule.Number)); err != nil {
		return fmt.Errorf("failed to delete rule [%d]: %s", rule.Number, strings.TrimSpace(trace))
	}
	log.Printf("Deleted rule [%d]", rule.Number)
	return nil
}

func (t *Tui) RemoveRule() {
	t.table.SetSelectedFunc(func(row int, column int) {
		t.table.SetSelectable(false, false)
		rule, ok := t.selectedRule(row)
		if !ok {
			t.app.SetFocus(t.table)
			return
		}
		t.CreateModal(fmt.Sprintf("Are you sure you want to remove rule [%d]?", rule.Number),
			func() {
				if err := t.DeleteRule(rule); err != nil {
					t.showError(err)
				}
			},
			func() {
				t.pages.HidePage("modal")
				t.app.SetFocus(t.table)
			},
			func() {
				t.pages.HidePage("modal")
				t.app.SetFocus(t.table)
			},
		)
	})
}

func (t *Tui) CreateMenu() {
	menuList := tview.NewList()
	menuList.
		AddItem("Search a rule", "", '/', func() {
			t.SearchForm()
			t.app.SetFocus(t.form)
			t.help.SetText("Press <Esc> to go back to the menu selection").SetBorderPadding(1, 0, 1, 0)
		}).
		AddItem("Add a rule", "", 'a', func() {
			t.CreateForm()
			t.app.SetFocus(t.form)
		}).
		AddItem("Edit a rule", "", 'e', func() {
			t.EditForm()
			t.app.SetFocus(t.table)
			t.help.SetText("Press <Esc> to go back to the menu selection").SetBorderPadding(1, 0, 1, 0)
		}).
		AddItem("Delete a rule", "", 'd', func() {
			t.RemoveRule()
			t.app.SetFocus(t.table)
			t.help.SetText("Press <Esc> to go back to the menu selection").SetBorderPadding(1, 0, 1, 0)
		}).
		AddItem("Disable ufw", "", 's', func() {
			t.CreateModal("Are you sure you want to disable ufw?",
				func() {
					shellout("ufw --force disable")
					t.app.Stop()
				},
				func() {
					t.pages.RemovePage("modal")
					t.app.SetFocus(t.menu)
				},
				func() {
					t.app.SetFocus(t.menu)
				},
			)
		}).
		AddItem("Reset rules", "", 'r', func() {
			t.CreateModal("Are you sure you want to reset all rules?",
				func() {
					shellout("ufw --force reset")
					t.app.Stop()
				},
				func() {
					t.app.SetFocus(t.menu)
				},
				func() {
					t.pages.RemovePage("modal")
					t.app.SetFocus(t.menu)
				},
			)
		}).
		AddItem("Exit", "", 'q', func() { t.app.Stop() })
	menuList.SetShortcutColor(t.color).SetBorderPadding(1, 0, 1, 1)
	t.menu.AddItem(menuList, 0, 1, true)
	t.menu.SetBorder(true).SetTitle(" Menu ")
}

func (t *Tui) Reset() {
	t.pages.HidePage("form")
	t.form.Clear(true)
	t.help.Clear()
	t.secondHelp.Clear()
}

func (t *Tui) CreateLayout() *tview.Pages {
	columns := tview.NewFlex().SetDirection(tview.FlexColumn)

	base := tview.NewFlex().AddItem(
		columns.
			AddItem(t.menu, 0, 2, true).
			AddItem(t.table, 0, 4, false),
		0, 1, true,
	)

	form := columns.AddItem(tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(t.help, 0, 2, false).
		AddItem(t.form, 0, 8, false).
		AddItem(t.secondHelp, 0, 2, false),
		0, 3, false,
	)

	t.pages.AddAndSwitchToPage("base", base, true)
	t.pages.AddPage("form", form, true, false)
	return t.pages
}

func (t *Tui) Build(rules []domain.Rule) {
	root := t.CreateLayout()

	status, _, err := shellout(" ufw status | awk -F': ' '/^Status:/ {printf \"%s\", $2}'")
	if err != nil {
		log.Printf("ufw status error: %v", err)
		t.app.Stop()
	}

	if status != "active" {
		t.pages.HidePage("base")
		t.CreateModal("ufw is disabled.\nDo you want to enable it?",
			func() {
				shellout("ufw --force enable")
			},
			func() {
				t.app.Stop()
			},
			func() {
				t.pages.HidePage("modal")
				t.pages.ShowPage("base")
				t.app.SetFocus(t.menu)
			},
		)
	}

	t.rules = rules
	t.CreateTable(rules)
	t.CreateMenu()

	if err := t.app.SetRoot(root, true).EnableMouse(false).Run(); err != nil {
		panic(err)
	}
}
