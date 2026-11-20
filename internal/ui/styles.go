package ui

import (
	"image/color"
	"strings"

	"charm.land/huh/v2"
	"charm.land/lipgloss/v2"
)

var (
	colorGreen  = lipgloss.Color("2")
	colorRed    = lipgloss.Color("1")
	colorYellow = lipgloss.Color("3")
	colorMuted  = lipgloss.Color("8")
	colorBright = lipgloss.Color("15")
	colorSelBg  = lipgloss.Color("237")
)

type styles struct {
	accent color.Color

	badge     lipgloss.Style
	active    lipgloss.Style
	inactive  lipgloss.Style
	muted     lipgloss.Style
	border    lipgloss.Style
	header    lipgloss.Style
	cell      lipgloss.Style
	statusOK  lipgloss.Style
	statusErr lipgloss.Style
	statusRun lipgloss.Style
	key       lipgloss.Style
	keyDesc   lipgloss.Style
	dialog    lipgloss.Style
	dlgTitle  lipgloss.Style
	button    lipgloss.Style
	buttonOn  lipgloss.Style
	formBox   lipgloss.Style
	formErr   lipgloss.Style
	empty     lipgloss.Style

	formTheme huh.Theme
}

func newStyles(accent color.Color) styles {
	return styles{
		accent:    accent,
		badge:     lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("0")).Background(accent).Padding(0, 1),
		active:    lipgloss.NewStyle().Foreground(colorGreen),
		inactive:  lipgloss.NewStyle().Foreground(colorRed).Bold(true),
		muted:     lipgloss.NewStyle().Foreground(colorMuted),
		border:    lipgloss.NewStyle().Foreground(accent),
		header:    lipgloss.NewStyle().Bold(true).Foreground(accent).Padding(0, 1),
		cell:      lipgloss.NewStyle().Padding(0, 1),
		statusOK:  lipgloss.NewStyle().Foreground(colorGreen),
		statusErr: lipgloss.NewStyle().Foreground(colorRed),
		statusRun: lipgloss.NewStyle().Foreground(colorYellow),
		key:       lipgloss.NewStyle().Bold(true).Foreground(accent),
		keyDesc:   lipgloss.NewStyle().Foreground(colorMuted),
		dialog:    lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(accent).Padding(1, 3),
		dlgTitle:  lipgloss.NewStyle().Bold(true).Foreground(accent),
		button:    lipgloss.NewStyle().Padding(0, 2).Foreground(colorBright).Background(colorSelBg),
		buttonOn:  lipgloss.NewStyle().Padding(0, 2).Bold(true).Foreground(lipgloss.Color("0")).Background(accent),
		formBox:   lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(accent).Padding(0, 2),
		formErr:   lipgloss.NewStyle().Foreground(colorRed).Bold(true),
		empty:     lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(colorMuted).Foreground(colorMuted).Padding(1, 4),
		formTheme: formTheme(accent),
	}
}

// cellStyle styles a table cell; action cells are colored by verdict.
func (s styles) cellStyle(col int, text string, selected bool) lipgloss.Style {
	st := s.cell
	if selected {
		st = st.Background(colorSelBg).Foreground(colorBright).Bold(true)
	}
	switch col {
	case colIndex:
		if !selected {
			st = st.Foreground(colorMuted)
		}
	case colAction:
		switch {
		case strings.HasPrefix(text, "ALLOW"):
			st = st.Foreground(colorGreen)
		case strings.HasPrefix(text, "LIMIT"):
			st = st.Foreground(colorYellow)
		default:
			st = st.Foreground(colorRed)
		}
	case colComment:
		st = st.Italic(true)
		if !selected {
			st = st.Foreground(colorMuted)
		}
	}
	return st
}

// formTheme is huh's Charm theme recolored with the accent color.
func formTheme(accent color.Color) huh.Theme {
	return huh.ThemeFunc(func(isDark bool) *huh.Styles {
		t := huh.ThemeCharm(isDark)

		t.Focused.Base = t.Focused.Base.BorderForeground(accent)
		t.Focused.Title = t.Focused.Title.Foreground(accent).Bold(true)
		t.Focused.SelectSelector = t.Focused.SelectSelector.Foreground(accent)
		t.Focused.NextIndicator = t.Focused.NextIndicator.Foreground(accent)
		t.Focused.PrevIndicator = t.Focused.PrevIndicator.Foreground(accent)
		t.Focused.TextInput.Prompt = t.Focused.TextInput.Prompt.Foreground(accent)
		t.Focused.FocusedButton = t.Focused.FocusedButton.Background(accent)

		t.Blurred = t.Focused
		t.Blurred.Base = t.Focused.Base.BorderStyle(lipgloss.HiddenBorder())
		t.Blurred.Card = t.Blurred.Base
		t.Blurred.Title = t.Blurred.Title.Foreground(colorMuted).Bold(false)
		t.Blurred.NextIndicator = lipgloss.NewStyle()
		t.Blurred.PrevIndicator = lipgloss.NewStyle()

		t.Group.Title = t.Focused.Title.MarginBottom(0)
		t.Group.Description = t.Focused.Description
		return t
	})
}
