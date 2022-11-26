package main

import (
	"log"
	"os/exec"
	"strconv"

	"github.com/peltho/tufw/internal/core/service"
)

func main() {
	cmd := exec.Command("id", "-u")
	output, err := cmd.Output()
	i, err := strconv.Atoi(string(output[:len(output)-1]))
	if i != 0 {
		log.Fatal("This program must be run as root! (sudo)")
	}

	tui := service.CreateApplication()
	tui.Init()
	data, err := tui.LoadTableData()
	if err != nil {
		log.Print(err)
	}
	tui.Build(data)
}
