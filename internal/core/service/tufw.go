package service

import (
	"fmt"
	"log"
	"regexp"
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/peltho/tufw/internal/core/domain"
	"github.com/peltho/tufw/internal/core/utils"
	"github.com/rivo/tview"
)

var NUMBER_OF_V6_RULES = 0
var shellout = utils.Shellout

type Tui struct {
	app        *tview.Application
	form       *tview.Form
	table      *tview.Table
	menu       *tview.Flex
	help       *tview.TextView
	secondHelp *tview.TextView
	pages      *tview.Pages
	color      tcell.Color
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

func (t *Tui) LoadSearchData(needle string) ([]string, error) {
	output, err := t.LoadUFWOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to load UFW output: %w", err)
	}

	var rules []string
	for _, row := range output {
		rules = append(rules, utils.FormatUfwRule(row))
	}

	var matches []string

	re, err := regexp.Compile("(?i)" + needle)
	if err != nil {
		return nil, fmt.Errorf("invalid search pattern: %w", err)
	}

	for _, rule := range rules {
		if re.MatchString(rule) {
			matches = append(matches, rule)
		}
	}

	return matches, nil
}

func (t *Tui) LoadUFWOutput() ([]string, error) {
	out, _, err := shellout("ufw status numbered | sed '/^$/d' | awk '{$2=$2};1' | tail -n +4")

	r := regexp.MustCompile(`\(v6\)`)
	matches := r.FindAllStringSubmatch(out, -1)
	NUMBER_OF_V6_RULES = len(matches)

	if err != nil {
		log.Printf("error: %v\n", err)
	}
	rows := strings.Split(out, "\n")

	return rows, nil
}

// @deprecated
func (t *Tui) LoadTableData() ([]string, error) {
	out, _, err := shellout("ufw status numbered | sed '/^$/d' | awk '{$2=$2};1' | tail -n +4 | sed -r 's/(\\[(\\s)([0-9]+)\\])/\\[\\3\\] /;s/(\\[([0-9]+)\\])/\\[\\2\\] /;s/\\(out\\)//;s/(\\w)\\s(\\(v6\\))/\\1/;s/([A-Z]{2,})\\s([A-Z]{2,3})/\\1-\\2/;s/^(.*)\\s([A-Z]{2,}(-[A-Z]{2,3})?)\\s(.*)\\s(on)\\s(.*)\\s(#.*)?/\\1_\\5_\\6 - \\2 \\4 \\7/;s/([A-Z][a-z]+\\/[a-z]{3})\\s(([A-Z]+).*)/\\1 - \\2/;s/(\\]\\s+)([0-9]{2,})\\s([A-Z]{2,}(-[A-Z]{2,3})?)/\\1Anywhere \\2 \\3/;s/(\\]\\s+)(([0-9]{1,3}\\.){3}[0-9]{1,3}(\\/[0-9]{1,2})?)\\s([A-Z]{2,}-[A-Z]{2,3})/\\1\\2 - \\5/;s/([A-Z][a-z]+)\\s(([A-Z]+).*)/\\1 - \\2/;s/(\\]\\s+)(.*)\\s([0-9]+)(\\/[a-z]{3})/\\1\\2\\4 \\3/;s/(\\]\\s+)\\/([a-z]{3})\\s/\\1\\2 /;s/^(.*)\\s(on)\\s(.*)\\s([A-Z]{2,}(-[A-Z]{2,3})?)\\s(.*)/\\1_\\2_\\3 - \\4 \\6/'")

	r := regexp.MustCompile(`\(v6\)`)
	matches := r.FindAllStringSubmatch(out, -1)
	NUMBER_OF_V6_RULES = len(matches)

	if err != nil {
		log.Printf("error: %v\n", err)
	}
	rows := strings.Split(out, "\n")

	return rows, nil
}

func (t *Tui) CreateTable(rows []string) {
	t.table.SetFixed(1, 1).SetBorderPadding(1, 0, 1, 1)

	columns := []string{"#", "To", "Port", "Action", "From", "Comment"}

	for c := range columns {
		t.table.SetCell(0, c, tview.NewTableCell(columns[c]).SetTextColor(t.color).SetAlign(tview.AlignCenter))
		if c >= len(columns) {
			break
		}

		for r, row := range rows {
			if r > len(rows)-1 {
				break
			}

			formattedRow := utils.FormatUfwRule(row)

			cellValues := utils.FillCell(formattedRow)
			if cellValues == nil {
				continue
			}

			// --- display values per column ---
			alignment := tview.AlignCenter
			value := ""
			switch c {
			case 0: // "#"
				value = cellValues.Index
			case 1: // "To"
				value = cellValues.To
			case 2: // "Port"
				value = cellValues.Port
			case 3: // "Action"
				value = cellValues.Action
			case 4: // "From"
				value = cellValues.From
			case 5: // "Comment"
				value = cellValues.Comment
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
	data, _ := t.LoadUFWOutput()

	t.CreateTable(data)
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
		data, _ := t.LoadSearchData(needle)

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

func updateInterfaces(interfaces []string, selectedIn string) []string {
	var filtered []string
	for _, iface := range interfaces {
		if iface != selectedIn {
			filtered = append(filtered, iface)
		}
	}

	return filtered
}

func (t *Tui) CreateForm() {
	t.help.SetText("Use <Tab> and <Enter> keys to navigate through the form").SetBorderPadding(1, 0, 1, 1)
	interfaces, _ := t.LoadInterfaces()

	var ifaceInDropDown, ifaceOutDropDown *tview.DropDown

	updateInterfaceDropDowns := func(changed string, selected string) {
		// Update the opposite dropdown based on selection
		switch changed {
		case "Interface":
			filtered := updateInterfaces(interfaces, selected)
			ifaceOutDropDown.SetOptions(filtered, nil)
		case "Interface out":
			filtered := updateInterfaces(interfaces, selected)
			ifaceInDropDown.SetOptions(filtered, nil)
		}
	}

	ifaceInDropDown = tview.NewDropDown().
		SetLabel("Interface").
		SetOptions(interfaces, func(text string, index int) {
			updateInterfaceDropDowns("Interface", text)
		})

	ifaceOutDropDown = tview.NewDropDown().
		SetLabel("Interface out").
		SetOptions(interfaces, func(text string, index int) {
			updateInterfaceDropDowns("Interface out", text)
		})

	t.form.AddInputField("To", "", 20, nil, nil).SetFieldTextColor(tcell.ColorWhite).
		AddInputField("Port", "", 20, utils.ValidatePort, nil).SetFieldTextColor(tcell.ColorWhite).
		AddDropDown("Action *", []string{"ALLOW IN", "DENY IN", "REJECT IN", "LIMIT IN", "ALLOW OUT", "DENY OUT", "REJECT OUT", "LIMIT OUT", "ALLOW FWD", "DENY FWD"}, 0, func(action string, index int) {
			if action == "ALLOW FWD" || action == "DENY FWD" {
				// Ensure the Interface out dropdown is in the form
				found := false
				for i := 0; i < t.form.GetFormItemCount(); i++ {
					if t.form.GetFormItem(i).GetLabel() == "Interface out" {
						found = true
						break
					}
				}
				if !found {
					t.form.AddFormItem(ifaceOutDropDown)
				}
			} else {
				// Remove Interface out if it exists
				for i := 0; i < t.form.GetFormItemCount(); i++ {
					if t.form.GetFormItem(i).GetLabel() == "Interface out" {
						t.form.RemoveFormItem(i)
						break
					}
				}
			}
		}).
		AddFormItem(ifaceInDropDown).
		AddDropDown("Protocol", []string{"", "tcp", "udp"}, 0, nil).
		AddInputField("From", "", 20, nil, nil).
		AddInputField("Comment", "", 40, nil, nil).
		AddButton("Save", func() { t.CreateRule() }).
		AddButton("Cancel", func() {
			t.Reset()
			t.app.SetFocus(t.menu)
		}).
		SetButtonTextColor(tcell.ColorWhite).
		SetButtonBackgroundColor(t.color).
		SetFieldBackgroundColor(t.color).
		SetLabelColor(tcell.ColorWhite)

	t.secondHelp.SetText("* Mandatory field\n\nPort, To and From fields respectively match any and Anywhere if left empty").SetTextColor(t.color).SetBorderPadding(0, 0, 1, 1)
}

func (t *Tui) ParseFormValues() domain.FormValues {
	var fv domain.FormValues

	for i := 0; i < t.form.GetFormItemCount(); i++ {
		item := t.form.GetFormItem(i)
		label := strings.TrimSpace(item.GetLabel())

		switch label {
		case "To":
			if f, ok := item.(*tview.InputField); ok {
				val := f.GetText()
				fv.To = val
			}

		case "Port":
			if f, ok := item.(*tview.InputField); ok {
				val := f.GetText()
				fv.Port = val
			}

		case "Action *":
			if d, ok := item.(*tview.DropDown); ok {
				_, val := d.GetCurrentOption()
				fv.Action = strings.ToLower(strings.ReplaceAll(val, " ", "-"))
			}

		case "Interface":
			if d, ok := item.(*tview.DropDown); ok {
				_, val := d.GetCurrentOption()
				fv.Interface = val
			}

		case "Interface out":
			if d, ok := item.(*tview.DropDown); ok {
				_, val := d.GetCurrentOption()
				fv.InterfaceOut = val
			}

		case "Protocol":
			if d, ok := item.(*tview.DropDown); ok {
				_, val := d.GetCurrentOption()
				fv.Protocol = val
			}

		case "From":
			if f, ok := item.(*tview.InputField); ok {
				val := f.GetText()
				fv.From = val
			}

		case "Comment":
			if f, ok := item.(*tview.InputField); ok {
				val := f.GetText()
				fv.Comment = val
			}
		}
	}

	return fv
}

func (t *Tui) EditForm() {
	t.table.SetSelectedFunc(func(row int, column int) {
		if row == 0 {
			t.app.SetFocus(t.table)
			return
		}
		t.help.SetText("Use <Tab> and <Enter> keys to navigate through the form").SetBorderPadding(1, 0, 1, 1)
		interfaces, _ := t.LoadInterfaces()

		toCell := t.table.GetCell(row, 1).Text
		fromCell := t.table.GetCell(row, 4).Text

		toValue, proto, ninterfaceOut := utils.ParseFromOrTo(toCell)
		fromValue, _, ninterface := utils.ParseFromOrTo(fromCell)
		interfaceOptionIndex := utils.ParseInterfaceIndex(ninterface, interfaces)

		protocolOptionIndex := 0
		switch proto {
		case "tcp":
			protocolOptionIndex = 1
		case "udp":
			protocolOptionIndex = 2
		default:
			protocolOptionIndex = 0
		}

		portValue := utils.ParsePort(t.table.GetCell(row, 2).Text)

		actionText := t.table.GetCell(row, 3).Text

		actionOptionIndex := 0
		switch actionText {
		case "ALLOW-IN":
			actionOptionIndex = 0
		case "DENY-IN":
			actionOptionIndex = 1
		case "REJECT-IN":
			actionOptionIndex = 2
		case "LIMIT-IN":
			actionOptionIndex = 3
		case "ALLOW-OUT":
			actionOptionIndex = 4
		case "DENY-OUT":
			actionOptionIndex = 5
		case "REJECT-OUT":
			actionOptionIndex = 6
		case "LIMIT-OUT":
			actionOptionIndex = 7
		case "ALLOW-FWD":
			actionOptionIndex = 8
		case "DENY-FWD":
			actionOptionIndex = 9
		}

		comment := strings.ReplaceAll(t.table.GetCell(row, 5).Text, "# ", "")

		var ifaceInDropDown, ifaceOutDropDown *tview.DropDown
		selectedIface := interfaces[interfaceOptionIndex]
		outInterfaces := updateInterfaces(interfaces, selectedIface)

		outInterfaceIndex := 0

		if actionText == "ALLOW-FWD" || actionText == "DENY-FWD" {
			outInterfaceIndex = utils.ParseInterfaceIndex(ninterfaceOut, outInterfaces)
		}

		ifaceInDropDown = tview.NewDropDown().
			SetLabel("Interface").
			SetOptions(interfaces, nil).
			SetCurrentOption(interfaceOptionIndex)

		ifaceOutDropDown = tview.NewDropDown().
			SetLabel("Interface out").
			SetOptions(outInterfaces, nil).
			SetCurrentOption(outInterfaceIndex)

		// --- Mutual exclusion logic
		ifaceInDropDown.SetSelectedFunc(func(text string, index int) {
			ifaceOutDropDown.SetOptions(updateInterfaces(interfaces, text), nil)
		})
		ifaceOutDropDown.SetSelectedFunc(func(text string, index int) {
			ifaceInDropDown.SetOptions(updateInterfaces(interfaces, text), nil)
		})

		// --- Show/hide Interface out
		showOrRemoveInterfaceOut := func(action string) {
			found := false
			for i := 0; i < t.form.GetFormItemCount(); i++ {
				if t.form.GetFormItem(i).GetLabel() == "Interface out" {
					found = true
					break
				}
			}

			if action == "ALLOW FWD" || action == "DENY FWD" {
				if !found {
					t.form.AddFormItem(ifaceOutDropDown)
				}
			} else if found {
				for i := 0; i < t.form.GetFormItemCount(); i++ {
					if t.form.GetFormItem(i).GetLabel() == "Interface out" {
						t.form.RemoveFormItem(i)
						break
					}
				}
			}
		}

		t.form.AddInputField("To", toValue, 20, nil, nil).SetFieldTextColor(tcell.ColorWhite).
			AddInputField("Port", portValue, 20, utils.ValidatePort, nil).SetFieldTextColor(tcell.ColorWhite).
			AddDropDown("Action *", []string{"ALLOW IN", "DENY IN", "REJECT IN", "LIMIT IN", "ALLOW OUT", "DENY OUT", "REJECT OUT", "LIMIT OUT", "ALLOW FWD", "DENY FWD"}, actionOptionIndex, func(action string, index int) {
				showOrRemoveInterfaceOut(action)
			}).
			AddDropDown("Interface", interfaces, interfaceOptionIndex, nil).
			AddDropDown("Protocol", []string{"", "tcp", "udp"}, protocolOptionIndex, nil).
			AddInputField("From", fromValue, 20, nil, nil).
			AddInputField("Comment", comment, 40, nil, nil)

		t.form.AddButton("Save", func() {
			editObject := t.ParseFormValues()
			t.EditRule(row, editObject)
			t.app.SetFocus(t.table)
		}).
			AddButton("Cancel", func() {
				t.Reset()
				t.help.SetText("Press <Esc> to go back to the menu selection").SetBorderPadding(1, 0, 1, 0)
				t.app.SetFocus(t.table)
			}).
			SetButtonTextColor(tcell.ColorWhite).
			SetButtonBackgroundColor(t.color).
			SetFieldBackgroundColor(t.color).
			SetLabelColor(tcell.ColorWhite)

		t.secondHelp.SetText("* Mandatory field\n\nPort, To and From fields respectively match any and Anywhere if left empty").
			SetTextColor(t.color).
			SetBorderPadding(0, 0, 1, 1)

		t.app.SetFocus(t.form)
	})
}

func (t *Tui) EditRule(position int, object domain.FormValues, rows ...int) *string {
	if object.Port == "" && object.Protocol == "" && object.Interface == "" && object.To == "" && object.From == "" {
		return nil
	}

	// For testing purposes (easy mock)
	var rowCount = t.table.GetRowCount()
	if len(rows) > 0 {
		rowCount = rows[0]
	}

	if object.To == "" || object.To == "Anywhere" {
		object.To = "any"
	}
	if object.From == "" || object.From == "Anywhere" {
		object.From = "any"
	}

	preCmd := strings.ToLower(strings.ReplaceAll(object.Action, "-", " "))
	if object.Interface != "" {
		preCmd = fmt.Sprintf("%s on %s", preCmd, object.Interface)
	}

	if strings.Contains(strings.ToLower(object.Action), "fwd") {
		tokens := strings.Split(object.Action, "-")
		if object.InterfaceOut != "" {
			preCmd = fmt.Sprintf("%s in on %s out on %s", strings.ToLower(tokens[0]), object.Interface, object.InterfaceOut)
		} else {
			preCmd = fmt.Sprintf("%s in on %s", strings.ToLower(tokens[0]), object.Interface)
		}
	}

	var parts []string
	parts = append(parts, "from", object.From, "to", object.To)

	if object.Protocol != "" {
		parts = append(parts, "proto", object.Protocol)
	}
	if object.Port != "" {
		parts = append(parts, "port", object.Port)
	}
	if object.Comment != "" {
		// Escape single quotes inside comment
		escaped := strings.ReplaceAll(object.Comment, "'", "''")
		parts = append(parts, "comment", fmt.Sprintf("'%s'", escaped))
	}

	cmd := strings.Join(parts, " ")

	dryCmd := fmt.Sprintf("ufw --dry-run %s %s", preCmd, cmd)
	baseCmd := fmt.Sprintf("ufw %s %s", preCmd, cmd)
	if position < rowCount-1 {
		dryCmd = fmt.Sprintf("ufw --dry-run insert %d %s %s", position, preCmd, cmd)
		baseCmd = fmt.Sprintf("ufw insert %d %s %s", position, preCmd, cmd)

		if strings.Contains(strings.ToLower(object.Action), "fwd") {
			dryCmd = fmt.Sprintf("ufw --dry-run route insert %d %s %s", position, preCmd, cmd)
			baseCmd = fmt.Sprintf("ufw route insert %d %s %s", position, preCmd, cmd)
		}
	}

	_, trace, err := shellout(dryCmd)
	if err == nil {
		// If replacing, delete first
		if _, trace, err := shellout(fmt.Sprintf("ufw --force delete %d", position)); err != nil {
			log.Printf("Failed to delete previous rule: %s", trace)
			return nil
		}

		// Apply rule
		if _, trace, err := shellout(baseCmd); err != nil {
			log.Printf("Failed to apply rule: %s - %s", trace, baseCmd)
			return nil
		}
		log.Printf("Editing rule: %s", baseCmd)
	} else {
		log.Printf("Invalid rule: %s - %s", trace, dryCmd)
		return nil
	}

	t.Reset()
	t.ReloadTable()
	return &baseCmd
}

func (t *Tui) CreateRule() {

	var ninterfaceOut string
	if item, ok := t.form.GetFormItemByLabel("Interface out").(*tview.DropDown); ok {
		_, ninterfaceOut = item.GetCurrentOption()
	}

	to := t.form.GetFormItemByLabel("To").(*tview.InputField).GetText()
	port := t.form.GetFormItemByLabel("Port").(*tview.InputField).GetText()
	_, ninterface := t.form.GetFormItemByLabel("Interface").(*tview.DropDown).GetCurrentOption()
	_, proto := t.form.GetFormItemByLabel("Protocol").(*tview.DropDown).GetCurrentOption()
	_, action := t.form.GetFormItemByLabel("Action *").(*tview.DropDown).GetCurrentOption()
	from := t.form.GetFormItemByLabel("From").(*tview.InputField).GetText()
	comment := t.form.GetFormItemByLabel("Comment").(*tview.InputField).GetText()

	// Guard clauses: no-op if everything is empty
	if port == "" && proto == "" && ninterface == "" && to == "" && from == "" {
		return
	}

	// Default "any" when empty
	if to == "" {
		to = "any"
	}
	if from == "" {
		from = "any"
	}

	// Build the preCmd part
	preCmd := strings.ToLower(action)
	if ninterface != "" {
		preCmd = fmt.Sprintf("%s on %s", preCmd, ninterface)
	}

	if strings.Contains(action, "FWD") {
		tokens := strings.Split(action, " ")
		if ninterfaceOut != "" {
			preCmd = fmt.Sprintf("route %s in on %s out on %s", strings.ToLower(tokens[0]), ninterface, ninterfaceOut)
		} else {
			preCmd = fmt.Sprintf("route %s in on %s", strings.ToLower(tokens[0]), ninterface)
		}
	}

	// Build the main rule parts
	var parts []string
	parts = append(parts, "from", from, "to", to)

	if proto != "" {
		parts = append(parts, "proto", proto)
	}
	if port != "" {
		parts = append(parts, "port", port)
	}
	if comment != "" {
		// Escape single quotes inside comment
		escaped := strings.ReplaceAll(comment, "'", "''")
		parts = append(parts, "comment", fmt.Sprintf("'%s'", escaped))
	}

	cmd := strings.Join(parts, " ")

	// Choose dry-run or actual
	dryCmd := "ufw --dry-run " + preCmd + " " + cmd
	baseCmd := "ufw " + preCmd + " " + cmd

	// Run dry-run first
	_, trace, err := shellout(dryCmd)
	if err == nil {
		// Apply rule
		if _, trace, err = shellout(baseCmd); err != nil {
			log.Printf("Failed to apply rule: %s - %s", trace, baseCmd)
			return
		}
		log.Printf("Creating rule: %s", baseCmd)
	} else {
		log.Printf("Invalid rule: %s - %s", trace, dryCmd)
		return
	}

	t.Reset()
	t.ReloadTable()
}

func (t *Tui) RemoveRule() {
	t.table.SetSelectedFunc(func(row int, column int) {
		t.table.SetSelectable(false, false)
		if row == 0 {
			t.app.SetFocus(t.table)
			return
		}
		t.CreateModal("Are you sure you want to remove this rule?",
			func() {
				shellout(fmt.Sprintf("ufw --force delete %d", row))
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

func (t *Tui) Build(data []string) {

	root := t.CreateLayout()

	if len(data) <= 1 {
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

	t.CreateTable(data)
	t.CreateMenu()

	if err := t.app.SetRoot(root, true).EnableMouse(false).Run(); err != nil {
		panic(err)
	}
}
