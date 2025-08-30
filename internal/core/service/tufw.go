package service

import (
	"fmt"
	"log"
	"regexp"
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/peltho/tufw/internal/core/utils"
	"github.com/rivo/tview"
)

var NUMBER_OF_V6_RULES = 0

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
	err, out, _ := utils.Shellout("ip link show | awk -F: '{ print $2 }' | sed -r 's/^[0-9]+//' | sed '/^$/d' | awk '{$2=$2};1'")
	if err != nil {
		log.Printf("error: %v\n", err)
	}

	interfaces := append(strings.Fields(out), "")

	return interfaces, nil
}

func (t *Tui) LoadSearchData(needle string) ([]string, error) {
	err, out, _ := utils.Shellout(fmt.Sprintf(
		"ufw status numbered | sed '/^$/d' | awk '{$2=$2};1' | tail -n +4 | sed -r 's/(\\[(\\s)([0-9]+)\\])/\\[\\3\\] /;s/(\\[([0-9]+)\\])/\\[\\2\\] /;s/\\(out\\)//;s/(\\w)\\s(\\(v6\\))/\\1/;s/([A-Z]{2,})\\s([A-Z]{2,3})/\\1-\\2/;s/^(.*)\\s([A-Z]{2,}(-[A-Z]{2,3})?)\\s(.*)\\s(on)\\s(.*)\\s(#.*)?/\\1_\\5_\\6 - \\2 \\4 \\7/;s/([A-Z][a-z]+\\/[a-z]{3})\\s(([A-Z]+).*)/\\1 - \\2/;s/(\\]\\s+)([0-9]{2,})\\s([A-Z]{2,}(-[A-Z]{2,3})?)/\\1Anywhere \\2 \\3/;s/(\\]\\s+)(([0-9]{1,3}\\.){3}[0-9]{1,3}(\\/[0-9]{1,2})?)\\s([A-Z]{2,}-[A-Z]{2,3})/\\1\\2 - \\5/;s/([A-Z][a-z]+)\\s(([A-Z]+).*)/\\1 - \\2/;s/(\\]\\s+)(.*)\\s([0-9]+)(\\/[a-z]{3})/\\1\\2\\4 \\3/;s/(\\]\\s+)\\/([a-z]{3})\\s/\\1\\2 /;s/^(.*)\\s(on)\\s(.*)\\s([A-Z]{2,}(-[A-Z]{2,3})?)\\s(.*)/\\1_\\2_\\3 - \\4 \\6/' | grep -E %v",
		needle,
	))
	if err != nil {
		return []string{}, nil
	}
	rows := strings.Split(out, "\n")

	return rows, nil
}

func (t *Tui) LoadTableData() ([]string, error) {
	err, out, _ := utils.Shellout("ufw status numbered | sed '/^$/d' | awk '{$2=$2};1' | tail -n +4 | sed -r 's/(\\[(\\s)([0-9]+)\\])/\\[\\3\\] /;s/(\\[([0-9]+)\\])/\\[\\2\\] /;s/\\(out\\)//;s/(\\w)\\s(\\(v6\\))/\\1/;s/([A-Z]{2,})\\s([A-Z]{2,3})/\\1-\\2/;s/^(.*)\\s([A-Z]{2,}(-[A-Z]{2,3})?)\\s(.*)\\s(on)\\s(.*)\\s(#.*)?/\\1_\\5_\\6 - \\2 \\4 \\7/;s/([A-Z][a-z]+\\/[a-z]{3})\\s(([A-Z]+).*)/\\1 - \\2/;s/(\\]\\s+)([0-9]{2,})\\s([A-Z]{2,}(-[A-Z]{2,3})?)/\\1Anywhere \\2 \\3/;s/(\\]\\s+)(([0-9]{1,3}\\.){3}[0-9]{1,3}(\\/[0-9]{1,2})?)\\s([A-Z]{2,}-[A-Z]{2,3})/\\1\\2 - \\5/;s/([A-Z][a-z]+)\\s(([A-Z]+).*)/\\1 - \\2/;s/(\\]\\s+)(.*)\\s([0-9]+)(\\/[a-z]{3})/\\1\\2\\4 \\3/;s/(\\]\\s+)\\/([a-z]{3})\\s/\\1\\2 /;s/^(.*)\\s(on)\\s(.*)\\s([A-Z]{2,}(-[A-Z]{2,3})?)\\s(.*)/\\1_\\2_\\3 - \\4 \\6/'")

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

	for c := 0; c < len(columns); c++ {
		t.table.SetCell(0, c, tview.NewTableCell(columns[c]).SetTextColor(t.color).SetAlign(tview.AlignCenter))
		if c >= len(columns) {
			break
		}

		for r, row := range rows {
			if r >= len(rows)-1 {
				break
			}

			cols := strings.Fields(row)
			alignment := tview.AlignCenter
			value := ""
			switch {
			case len(cols) < len(columns) && c >= len(cols):
				value = ""
			case c >= 5:
				value = strings.ReplaceAll(strings.Join(cols[c:], " "), "#", "")
				alignment = tview.AlignLeft
			default:
				value = strings.ReplaceAll(cols[c], "_", " ")
			}

			t.table.SetCell(r+1, c, tview.NewTableCell(value).SetTextColor(tcell.ColorWhite).SetAlign(alignment).SetExpansion(1))
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
	data, _ := t.LoadTableData()
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

func updateInterfaceOut(form *tview.Form, action string, interfaces []string, selectedIn string) {
	if action != "ALLOW FWD" && action != "DENY FWD" {
		return
	}

	var filtered []string
	for _, iface := range interfaces {
		if iface != selectedIn {
			filtered = append(filtered, iface)
		}
	}

	// Add new one
	form.AddDropDown("Interface out", filtered, 0, nil)
}

func (t *Tui) CreateForm() {
	t.help.SetText("Use <Tab> and <Enter> keys to navigate through the form").SetBorderPadding(1, 0, 1, 1)
	interfaces, _ := t.LoadInterfaces()

	t.form.AddInputField("To", "", 20, nil, nil).SetFieldTextColor(tcell.ColorWhite).
		AddInputField("Port", "", 20, utils.ValidatePort, nil).SetFieldTextColor(tcell.ColorWhite).
		AddDropDown("Interface", interfaces, len(interfaces), func(option string, index int) {
			if item, ok := t.form.GetFormItemByLabel("Action *").(*tview.DropDown); ok {
				_, action := item.GetCurrentOption()
				updateInterfaceOut(t.form, action, interfaces, option)
			}
		}).
		AddDropDown("Protocol", []string{"", "tcp", "udp"}, 0, nil).
		AddDropDown("Action *", []string{"ALLOW IN", "DENY IN", "REJECT IN", "LIMIT IN", "ALLOW OUT", "DENY OUT", "REJECT OUT", "LIMIT OUT", "ALLOW FWD", "DENY FWD"}, 0, nil).
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

func (t *Tui) EditForm() { // TODO: Fix it for forwarding as well
	t.table.SetSelectedFunc(func(row int, column int) {
		if row == 0 {
			t.app.SetFocus(t.table)
			return
		}
		t.help.SetText("Use <Tab> and <Enter> keys to navigate through the form").SetBorderPadding(1, 0, 1, 1)
		interfaces, _ := t.LoadInterfaces()

		to := t.table.GetCell(row, 1).Text
		from := t.table.GetCell(row, 4).Text

		toValue := utils.ParseIPAddress(to)
		fromValue := utils.ParseIPAddress(from)

		proto := utils.ParseProtocol(to, from)
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
		interfaceOptionIndex := utils.ParseInterfaceIndex(to, interfaces)

		actionOptionIndex := 0
		switch t.table.GetCell(row, 3).Text {
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
		}

		comment := strings.ReplaceAll(t.table.GetCell(row, 5).Text, "# ", "")

		t.form.AddInputField("To", toValue, 20, nil, nil).SetFieldTextColor(tcell.ColorWhite).
			AddInputField("Port", portValue, 20, utils.ValidatePort, nil).SetFieldTextColor(tcell.ColorWhite).
			AddDropDown("Interface", interfaces, interfaceOptionIndex, nil).
			AddDropDown("Protocol", []string{"", "tcp", "udp"}, protocolOptionIndex, nil).
			AddDropDown("Action *", []string{"ALLOW IN", "DENY IN", "REJECT IN", "LIMIT IN", "ALLOW OUT", "DENY OUT", "REJECT OUT", "LIMIT OUT"}, actionOptionIndex, nil).
			AddInputField("From", fromValue, 20, nil, nil).
			AddInputField("Comment", comment, 40, nil, nil).
			AddButton("Save", func() {
				t.CreateRule(row)
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

func (t *Tui) CreateRule(position ...int) {

	var ninterfaceOut = ""
	if item, ok := t.form.GetFormItemByLabel("Interface out").(*tview.DropDown); ok {
		_, ninterfaceOut = item.GetCurrentOption()
	}

	to := t.form.GetFormItem(0).(*tview.InputField).GetText()
	port := t.form.GetFormItem(1).(*tview.InputField).GetText()
	_, ninterface := t.form.GetFormItem(2).(*tview.DropDown).GetCurrentOption()
	_, proto := t.form.GetFormItemByLabel("Protocol").(*tview.DropDown).GetCurrentOption()
	_, action := t.form.GetFormItemByLabel("Action *").(*tview.DropDown).GetCurrentOption()
	from := t.form.GetFormItemByLabel("From").(*tview.InputField).GetText()
	comment := t.form.GetFormItemByLabel("Comment").(*tview.InputField).GetText()

	dryCmd := "ufw --dry-run "
	baseCmd := "ufw "

	if len(position) > 0 && position[0] < t.table.GetRowCount()-NUMBER_OF_V6_RULES-1 {
		dryCmd = fmt.Sprintf("ufw --dry-run insert %d ", position[0])
		baseCmd = fmt.Sprintf("ufw insert %d ", position[0])
	}

	if ninterface != "" && (port != "" || proto != "") {
		return
	}

	if port == "" && proto == "" && ninterface == "" && to == "" && from == "" {
		return
	}

	toValue := to
	if to == "" {
		toValue = "any"
	}
	fromValue := from
	if from == "" {
		fromValue = "any"
	}

	cmd := ""
	preCmd := fmt.Sprintf("%s from ", strings.ToLower(action))
	if ninterface != "" {
		preCmd = fmt.Sprintf("%s on %s from ", strings.ToLower(action), ninterface)
		if action == "ALLOW FWD" {
			preCmd = fmt.Sprintf("allow in on %s out on %s from ", ninterface, ninterfaceOut)
		}
		if action == "DENY FWD" {
			preCmd = fmt.Sprintf("deny in on %s out on %s from ", ninterface, ninterfaceOut)
		}
	}

	if port != "" && proto == "" {
		cmd = fmt.Sprintf("%s to %s port %s comment '%s'", fromValue, toValue, port, comment)
	}
	if port == "" && proto != "" {
		cmd = fmt.Sprintf("%s proto %s to %s comment '%s'", fromValue, proto, toValue, comment)
	}
	if port != "" && proto != "" {
		cmd = fmt.Sprintf("%s proto %s to %s port %s comment '%s'", fromValue, proto, toValue, port, comment)
	}
	if port == "" && proto == "" {
		cmd = fmt.Sprintf("%s to %s comment '%s'", fromValue, toValue, comment)
	}
	if ninterface != "" && to == "" {
		cmd = fmt.Sprintf("%s comment '%s'", fromValue, comment)
	}

	// Dry-run
	err, _, _ := utils.Shellout(dryCmd + preCmd + cmd)
	if err == nil {
		// Delete first
		if len(position) > 0 {
			utils.Shellout(fmt.Sprintf("ufw --force delete %d", position[0]))
		}

		// Then create
		err, _, _ = utils.Shellout(baseCmd + preCmd + cmd)
		if err != nil {
			log.Print(err)
		}
	}
	if err != nil {
		log.Print(err)
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
				utils.Shellout(fmt.Sprintf("ufw --force delete %d", row))
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
					utils.Shellout("ufw --force disable")
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
					utils.Shellout("ufw --force reset")
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
				utils.Shellout("ufw --force enable")
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
