package main

import (
	"flag"
	"fmt"
	"image/color"
	"io"
	"log"
	"os"
	"os/exec"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/peltho/tufw/internal/core/service"
	"github.com/peltho/tufw/internal/ui"
)

// Accent colors use the terminal's ANSI palette so they match its theme.
var accents = map[string]color.Color{
	"red":   lipgloss.Color("1"),
	"green": lipgloss.Color("2"),
	"blue":  lipgloss.Color("4"),
	"cyan":  lipgloss.Color("6"),
}

func main() {
	colorFlag := flag.String("color", "cyan", "Accent color (red, green, blue, cyan)")
	logFlag := flag.String("log", "", "Log everything into the given file")
	flag.Parse()

	accent, ok := accents[*colorFlag]
	if !ok {
		log.Fatalf("Invalid color: %s. Allowed values are red, green, blue, cyan.", *colorFlag)
	}

	if os.Geteuid() != 0 {
		log.Fatal("This program must be run as root! (sudo)")
	}

	if _, err := exec.LookPath("ufw"); err != nil {
		log.Fatal("Cannot find ufw. Is it installed?")
	}

	fw := service.New()
	if _, err := fw.LoadRules(); err != nil {
		log.Fatal(err)
	}

	if *logFlag != "" {
		f, err := os.OpenFile(*logFlag, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		log.SetOutput(f)
	} else {
		log.SetOutput(io.Discard)
	}

	if _, err := tea.NewProgram(ui.New(fw, accent)).Run(); err != nil {
		fmt.Fprintln(os.Stderr, "tufw:", err)
		os.Exit(1)
	}
}
