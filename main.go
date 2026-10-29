package main

import "github.com/KilluaAoki/XNode/cmd"

var (
	version   = "dev"
	buildTime = "unknown"
)

func main() {
	cmd.Execute(version, buildTime)
}
