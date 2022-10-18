package main

import (
	"bytes"
	"fmt"
	"log"
	"os/exec"
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
	app   *tview.Application
	form  *tview.Form
	table *tview.Table
	menu  *tview.Flex
	help  *tview.TextView
	pages *tview.Pages
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
	t.pages = tview.NewPages()
}

func (t *Tui) LoadTableData() ([]string, error) {
	err, out, _ := shellout("ufw status | sed '/^$/d' | awk '{$2=$2};1' | tail -n +4")
	if err != nil {
		log.Printf("error: %v\n", err)
	}

	rows := strings.Split(out, "\n")

	return rows, nil
}

func (t *Tui) CreateTable(rows []string) {
	t.table.SetFixed(1, 1).SetBorderPadding(1, 0, 1, 1)

	columns := []string{"#", "To", "Action", "From", "Comment"}

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
			if len(cols) < len(columns) && c >= len(cols) {
				t.table.SetCell(r+1, c+1, tview.NewTableCell(value).SetTextColor(tcell.ColorWhite).SetAlign(tview.AlignCenter).SetExpansion(1))
			} else {

				// Conditional statement for displaying Comments if any
				if c >= 3 {
					value = strings.Join(cols[c:], " ")
				} else {
					value = cols[c]
				}

				t.table.SetCell(r+1, c+1, tview.NewTableCell(value).SetTextColor(tcell.ColorWhite).SetAlign(tview.AlignCenter).SetExpansion(1))
			}
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
	}).SetSelectedFunc(func(row int, column int) {
		t.table.SetSelectable(false, false)
		t.CreateModal("Are you sure you want to remove this rule?",
			func() {
				shellout(fmt.Sprintf("ufw --force delete %d", row))
			}, func() {
				t.pages.HidePage("modal")
				t.app.SetFocus(t.table)
			})
	})
}

func (t *Tui) ReloadTable() {
	t.table.Clear()
	data, _ := t.LoadTableData()
	t.CreateTable(data)
}

func (t *Tui) CreateModal(text string, action func(), finally func()) {
	modal := tview.NewModal()
	t.pages.AddPage("modal", modal.SetText(text).AddButtons([]string{"Confirm", "Cancel"}).SetDoneFunc(func(i int, label string) {
		if label == "Confirm" {
			action()
			t.ReloadTable()
		}
		modal.ClearButtons()
		finally()
	}), true, true)
}

func (t *Tui) CreateHelp(text string) {
	t.help.SetText(text).SetBorderPadding(1, 0, 1, 0)
}

func (t *Tui) CreateMenu() {
	menuList := tview.NewList()
	menuList.
		AddItem("Add a rule", "", 'a', func() {
			t.CreateForm()
			t.app.SetFocus(t.form)
		}).
		AddItem("Remove a rule", "", 'd', func() {
			t.app.SetFocus(t.table)
			t.CreateHelp("Press <Esc> to go back to the menu selection")
		}).
		AddItem("Disable ufw", "", 's', func() {
			t.CreateModal("Are you sure you want to disable ufw?",
				func() {
					shellout("ufw --force disable")
				},
				func() {
					t.app.Stop()
				},
			)
		}).
		AddItem("Reset rules", "", 'r', func() {
			t.CreateModal("Are you sure you want to reset all rules?",
				func() {
					shellout("ufw --force reset")
				},
				func() {
					t.app.Stop()
				},
			)
		}).
		AddItem("Exit", "", 'q', func() { t.app.Stop() })
	menuList.SetBorderPadding(1, 0, 1, 1)
	t.menu.AddItem(menuList, 0, 1, true)
	t.menu.SetBorder(true).SetTitle(" Menu ")
}

func (t *Tui) CreateForm() {
	t.CreateHelp("Use <Tab> and <Enter> keys to navigate through the form")
	t.form.AddInputField("To", "", 20, nil, nil).
		AddDropDown("Protocol", []string{"tcp", "udp"}, 0, nil).
		AddDropDown("Action", []string{"ALLOW", "DENY", "REJECT", "LIMIT"}, 0, nil).
		AddInputField("From", "", 20, nil, nil).
		AddInputField("Comment", "", 40, nil, nil).
		AddButton("Save", t.CreateRule).
		AddButton("Cancel", t.Cancel)
}

func (t *Tui) Reset() {
	t.pages.HidePage("form")
	t.form.Clear(true)
	t.help.Clear()
	t.app.SetFocus(t.menu)
}

func (t *Tui) CreateRule() {
	to := t.form.GetFormItem(0).(*tview.InputField).GetText()
	_, proto := t.form.GetFormItem(1).(*tview.DropDown).GetCurrentOption()
	_, action := t.form.GetFormItem(2).(*tview.DropDown).GetCurrentOption()
	from := t.form.GetFormItem(3).(*tview.InputField).GetText()
	comment := t.form.GetFormItem(4).(*tview.InputField).GetText()

	if to == "" || from == "" {
		return
	}

	cmd := fmt.Sprintf("ufw %s from %s proto %s to any port %s comment '%s'", strings.ToLower(action), from, proto, to, comment)
	err, _, _ := shellout(cmd)
	if err != nil {
		log.Print(err)
	}
	t.Reset()
	t.ReloadTable()
}

func (t *Tui) Cancel() {
	t.Reset()
}

func (t *Tui) CreateLayout() *tview.Pages {
	columns := tview.NewFlex().SetDirection(tview.FlexColumn)

	base := tview.NewFlex().AddItem(
		columns.
			AddItem(t.menu, 0, 1, true).
			AddItem(t.table, 0, 4, false),
		0, 1, true,
	)

	form := columns.AddItem(tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(t.help, 0, 1, false).
		AddItem(t.form, 0, 8, false),
		0, 3, false,
	)

	t.pages.AddAndSwitchToPage("base", base, true)
	t.pages.AddPage("form", form, false, false)
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
		tui.CreateModal("ufw is disabled. Do you want to enable it?",
			func() {
				shellout("ufw --force enable")
			},
			func() {
				tui.pages.HidePage("modal")
				tui.pages.ShowPage("base")
				tui.app.SetFocus(tui.menu)
			})
	}

	tui.CreateTable(data)
	tui.CreateMenu()

	if err := tui.app.SetRoot(root, true).EnableMouse(false).Run(); err != nil {
		panic(err)
	}
}
