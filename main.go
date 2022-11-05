package main

import (
	"bytes"
	"fmt"
	"log"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

func shellout(command string) (error, string, string) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd := exec.Command("bash", "-c", command)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return err, stdout.String(), stderr.String()
}

type Tui struct {
	app        *tview.Application
	form       *tview.Form
	table      *tview.Table
	menu       *tview.Flex
	help       *tview.TextView
	secondHelp *tview.TextView
	pages      *tview.Pages
}

func CreateApplication() *Tui {
	return new(Tui)
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
	err, out, _ := shellout("ip link show | awk -F: '{ print $2 }' | sed -r 's/^[0-9]+//' | sed '/^$/d' | awk '{$2=$2};1'")
	if err != nil {
		log.Printf("error: %v\n", err)
	}
	return strings.Split(out, "\n"), nil
}

func (t *Tui) LoadTableData() ([]string, error) {
	err, out, _ := shellout("ufw status | sed '/^$/d' | awk '{$2=$2};1' | tail -n +4 | sed -r 's/(\\w)\\s(\\(v6\\))/\\1/;s/([A-Z]{2,})\\s([A-Z]{2,3})/\\1-\\2/;s/^(.*)\\s([A-Z]{2,}(-[A-Z]{2,3})?)\\s(.*)(\\/[a-z]{3})/\\1\\5 \\2\\3 \\4/;s/^(.*)\\s([A-Z]{2,}(-[A-Z]{2,3})?)\\s(.*)\\s(on)\\s(.*)#?/\\1_\\5_\\6 - \\2 \\4/;s/^(.*)\\s(([0-9]+)\\/([a-z]{3}))/\\1\\/\\4 \\3/;s/(^[0-9]+)\\/([a-z]{3})/\\2 \\1/;s/(\\w+)\\s(on)\\s(\\w+)/\\1-\\2-\\3 -/;s/^([A-Z][a-z]+\\/[a-z]{3})\\s(([A-Z]+).*)/\\1 - \\2/'")

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
		t.table.SetCell(0, c, tview.NewTableCell(columns[c]).SetTextColor(tcell.ColorDarkCyan).SetAlign(tview.AlignCenter))
		if c >= len(columns)-1 {
			break
		}

		for r, row := range rows {
			if r >= len(rows)-1 {
				break
			}

			t.table.SetCell(r+1, 0, tview.NewTableCell(fmt.Sprintf("[%d]", r+1)).SetTextColor(tcell.ColorDarkCyan).SetAlign(tview.AlignCenter).SetExpansion(1))

			cols := strings.Fields(row)

			value := ""
			switch {
			case len(cols) < len(columns) && c >= len(cols):
				value = ""
			case c >= 4:
				value = strings.ReplaceAll(strings.Join(cols[c:], " "), "#", "")
			default:
				value = strings.ReplaceAll(cols[c], "-", " ")
			}

			t.table.SetCell(r+1, c+1, tview.NewTableCell(value).SetTextColor(tcell.ColorWhite).SetAlign(tview.AlignCenter).SetExpansion(1))
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

func (t *Tui) CreateForm() {
	t.help.SetText("Use <Tab> and <Enter> keys to navigate through the form").SetBorderPadding(1, 0, 1, 1)
	interfaces, _ := t.LoadInterfaces()

	t.form.AddInputField("To", "", 20, nil, nil).SetFieldTextColor(tcell.ColorWhite).
		AddInputField("Port", "", 20, validatePort, nil).SetFieldTextColor(tcell.ColorWhite).
		AddDropDown("Interface", interfaces, len(interfaces), nil).
		AddDropDown("Protocol", []string{"", "tcp", "udp"}, 0, nil).
		AddDropDown("Action *", []string{"ALLOW", "DENY", "REJECT", "LIMIT", "ALLOW OUT", "DENY OUT", "REJECT OUT", "LIMIT OUT"}, 0, nil).
		AddInputField("From", "", 20, nil, nil).
		AddInputField("Comment", "", 40, nil, nil).
		AddButton("Save", func() { t.CreateRule() }).
		AddButton("Cancel", t.Reset).
		SetButtonTextColor(tcell.ColorWhite).
		SetButtonBackgroundColor(tcell.ColorDarkCyan).
		SetFieldBackgroundColor(tcell.ColorDarkCyan).
		SetLabelColor(tcell.ColorWhite)

	t.secondHelp.SetText("* Mandatory field\n\nTo and From fields match any and Anywhere if left empty").SetTextColor(tcell.ColorDarkCyan).SetBorderPadding(0, 0, 1, 1)
}

func validatePort(text string, ch rune) bool {
	_, err := strconv.Atoi(text)
	return err == nil
}

func (t *Tui) EditForm() {
	t.table.SetSelectedFunc(func(row int, column int) {
		if row == 0 {
			t.app.SetFocus(t.table)
			return
		}
		t.help.SetText("Use <Tab> and <Enter> keys to navigate through the form").SetBorderPadding(1, 0, 1, 1)
		interfaces, _ := t.LoadInterfaces()

		to := t.table.GetCell(row, 1).Text
		rip := regexp.MustCompile(`(([0-9]{1,3}\.){3}[0-9]{1,3})(/[0-9]{1,2})?`)
		rproto := regexp.MustCompile(`/?([a-z]{3})`)
		matchIP := rip.FindStringSubmatch(to)
		matchProto := rproto.FindStringSubmatch(to)

		toValue := ""
		proto := ""
		if len(matchIP) > 0 {
			toValue = matchIP[0]
		}
		if len(matchProto) > 1 {
			proto = matchProto[1]
		}

		portValue := ""
		port := t.table.GetCell(row, 2).Text
		rport := regexp.MustCompile(`([0-9]*)(/[a-z]{3})?`)
		matchPort := rport.FindStringSubmatch(port)
		portValue = matchPort[1]

		interfaceOptionIndex := len(interfaces)

		protocolOptionIndex := 0
		switch proto {
		case "tcp":
			protocolOptionIndex = 1
		case "udp":
			protocolOptionIndex = 2
		default:
			protocolOptionIndex = 0
		}

		actionOptionIndex := 0
		switch t.table.GetCell(row, 3).Text {
		case "ALLOW":
			actionOptionIndex = 0
		case "DENY":
			actionOptionIndex = 1
		case "REJECT":
			actionOptionIndex = 2
		case "LIMIT":
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

		from := t.table.GetCell(row, 4).Text
		fromValue := from
		if t.table.GetCell(row, 4).Text == "Anywhere" {
			fromValue = ""
		}
		comment := strings.ReplaceAll(t.table.GetCell(row, 5).Text, "# ", "")

		t.form.AddInputField("To", toValue, 20, nil, nil).SetFieldTextColor(tcell.ColorWhite).
			AddInputField("Port", portValue, 20, validatePort, nil).SetFieldTextColor(tcell.ColorWhite).
			AddDropDown("Interface", interfaces, interfaceOptionIndex, nil).
			AddDropDown("Protocol", []string{"", "tcp", "udp"}, protocolOptionIndex, nil).
			AddDropDown("Action *", []string{"ALLOW", "DENY", "REJECT", "LIMIT", "ALLOW OUT", "DENY OUT", "REJECT OUT", "LIMIT OUT"}, actionOptionIndex, nil).
			AddInputField("From", fromValue, 20, nil, nil).
			AddInputField("Comment", comment, 40, nil, nil).
			AddButton("Save", func() {
				t.CreateRule(row)
				t.table.SetSelectable(false, false)
			}).
			AddButton("Cancel", func() {
				t.Reset()
				t.table.SetSelectable(false, false)
			}).
			SetButtonTextColor(tcell.ColorWhite).
			SetButtonBackgroundColor(tcell.ColorDarkCyan).
			SetFieldBackgroundColor(tcell.ColorDarkCyan).
			SetLabelColor(tcell.ColorWhite)

		t.secondHelp.SetText("* Mandatory field\n\nTo and From fields match any and Anywhere if left empty").
			SetTextColor(tcell.ColorDarkCyan).
			SetBorderPadding(0, 0, 1, 1)

		t.app.SetFocus(t.form)
	})
}

func (t *Tui) CreateRule(position ...int) {
	to := t.form.GetFormItem(0).(*tview.InputField).GetText()
	port := t.form.GetFormItem(1).(*tview.InputField).GetText()
	_, ninterface := t.form.GetFormItem(2).(*tview.DropDown).GetCurrentOption()
	_, proto := t.form.GetFormItem(3).(*tview.DropDown).GetCurrentOption()
	_, action := t.form.GetFormItem(4).(*tview.DropDown).GetCurrentOption()
	from := t.form.GetFormItem(5).(*tview.InputField).GetText()
	comment := t.form.GetFormItem(6).(*tview.InputField).GetText()

	dryCmd := "ufw --dry-run "
	baseCmd := "ufw "
	if len(position) > 0 && position[0] < t.table.GetRowCount()-1 {
		dryCmd = fmt.Sprintf("ufw --dry-run insert %d ", position[0])
		baseCmd = fmt.Sprintf("ufw insert %d ", position[0])
	}

	if port != "" && ninterface != "" {
		return
	}

	if proto != "" && (from == "" || to == "") {
		return
	}

	if port != "" && (from == "" || to == "") {
		return
	}

	if (proto == "" || port == "") && from == "" && to == "" && ninterface == "" {
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
	preCmd := fmt.Sprintf("%s ", strings.ToLower(action))
	if ninterface != "" {
		preCmd = fmt.Sprintf("%s on %s ", strings.ToLower(action), ninterface)
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
	if ninterface != "" && (to == "" || from == "") {
		cmd = fmt.Sprintf("comment '%s'", comment)
	}

	// Dry-run
	err, _, _ := shellout(dryCmd + preCmd + cmd)
	if err == nil {
		// Delete first
		if len(position) > 0 {
			shellout(fmt.Sprintf("ufw --force delete %d", position[0]))
		}

		// Then create
		err, _, _ = shellout(baseCmd + preCmd + cmd)
		if err != nil {
			log.Print(err)
		}
	}
	if err != nil {
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
		AddItem("Add a rule", "", 'a', func() {
			t.CreateForm()
			t.app.SetFocus(t.form)
		}).
		AddItem("Edit a rule", "", 'e', func() {
			t.EditForm()
			t.app.SetFocus(t.table)
		}).
		AddItem("Remove a rule", "", 'd', func() {
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
	menuList.SetShortcutColor(tcell.ColorDarkCyan).SetBorderPadding(1, 0, 1, 1)
	t.menu.AddItem(menuList, 0, 1, true)
	t.menu.SetBorder(true).SetTitle(" Menu ")
}

func (t *Tui) Reset() {
	t.pages.HidePage("form")
	t.form.Clear(true)
	t.help.Clear()
	t.secondHelp.Clear()
	t.app.SetFocus(t.menu)
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

func main() {
	tui := CreateApplication()
	tui.Init()
	data, err := tui.LoadTableData()
	if err != nil {
		log.Print(err)
	}

	root := tui.CreateLayout()

	if len(data) <= 1 {
		tui.pages.HidePage("base")
		tui.CreateModal("ufw is disabled.\nDo you want to enable it?",
			func() {
				shellout("ufw --force enable")
			},
			func() {
				tui.app.Stop()
			},
			func() {
				tui.pages.HidePage("modal")
				tui.pages.ShowPage("base")
				tui.app.SetFocus(tui.menu)
			},
		)
	}

	tui.CreateTable(data)
	tui.CreateMenu()

	if err := tui.app.SetRoot(root, true).EnableMouse(false).Run(); err != nil {
		panic(err)
	}
}
