package main

import (
	"flag"
	"log"
	"os/exec"
	"strconv"

	"github.com/gdamore/tcell/v2"
	"github.com/peltho/tufw/internal/core/service"
)

const (
	Green tcell.Color = tcell.ColorGreen
	Red   tcell.Color = tcell.ColorRed
	Blue  tcell.Color = tcell.ColorBlue
	Cyan  tcell.Color = tcell.ColorDarkCyan
)

func main() {
	cmd := exec.Command("id", "-u")
	output, err := cmd.Output()
	i, err := strconv.Atoi(string(output[:len(output)-1]))
	if i != 0 {
		log.Fatal("This program must be run as root! (sudo)")
	}

	cmd = exec.Command("ufw", "status")
	_, err = cmd.Output()
	if err != nil {
		log.Fatal("Cannot find ufw. Is it installed?")
	}

	colorFlag := flag.String("color", "cyan", "Color value (red, green, blue)")
	flag.Parse()

	var color tcell.Color
	switch *colorFlag {
	case "red":
		color = Red
	case "green":
		color = Green
	case "blue":
		color = Blue
	case "cyan":
		color = Cyan
	default:
		log.Fatalf("Invalid color: %s. Allowed values are red, green, blue.", *colorFlag)
	}

	tui := service.CreateApplication(color)
	tui.Init()
	data, err := tui.LoadTableData()
	if err != nil {
		log.Print(err)
	}
	tui.Build(data)
}
