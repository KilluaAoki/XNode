package cmd

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/term"
)

const (
	appName           = "xnode"
	defaultHealthPort = 65530
	repoURL           = "https://github.com/KilluaAoki/XNode"
	downloadBase      = repoURL + "/releases"
)

var (
	version   = "dev"
	buildTime = "unknown"
)

func Execute(ver, built string) {
	if ver != "" {
		version = ver
	}
	if built != "" {
		buildTime = built
	}
	prepareConsole()
	initLang()
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		if interactive() {
			return runMenu()
		}
		printUsage()
		return nil
	}
	rest := args[1:]
	switch args[0] {
	case "server", "run":
		return runServer(rest)
	case "menu":
		return runMenu()
	case "install":
		return runInstall(rest)
	case "upgrade", "update":
		return runUpgrade(rest)
	case "uninstall":
		return runUninstall(rest)
	case "start", "stop", "restart", "enable", "disable":
		return detectServiceManager().control(args[0])
	case "status":
		return runStatus()
	case "log", "logs":
		return detectServiceManager().logs(rest)
	case "list":
		return runList(rest)
	case "instance":
		return runInstance(rest)
	case "health":
		return runHealth()
	case "bind":
		return runBind(rest)
	case "unbind":
		return runBind(append([]string{"remove"}, rest...))
	case "config":
		return runConfig(rest)
	case "x25519":
		return runX25519(rest)
	case "mlkem768":
		return runMLKEM768(rest)
	case "bbr":
		return runBBR()
	case "version", "-v", "--version":
		fmt.Printf("%s %s (built %s)\n", appName, version, buildTime)
		return nil
	case "help", "-h", "--help":
		printUsage()
		return nil
	default:
		printUsage()
		return fmt.Errorf("unknown command: %s", args[0])
	}
}

func printUsage() {
	fmt.Println(`Usage: xnode [command]

  xnode                          interactive menu
  xnode server -c FILE [-e FILE] run the node
  xnode install [flags]          install or add a binding (see xnode install -h)
  xnode upgrade [VERSION]        upgrade to the latest or given release
  xnode uninstall [--purge] [-y] remove service and binary
  xnode start|stop|restart       control the service
  xnode enable|disable           toggle autostart
  xnode status                   service, health and bindings
  xnode log [args]               follow service logs
  xnode list [--output json]     list bindings
  xnode instance get ID          show one binding
  xnode health                   query the local health endpoint
  xnode bind add-node|add-machine [flags]
  xnode bind remove ID | remove-node --panel URL --node-id N | remove-machine --panel URL --machine-id N
  xnode config [show|edit|path]  view or edit the config file
  xnode x25519 [-i KEY]          generate a REALITY key pair
  xnode mlkem768 [-i SEED]       generate a VLESS encryption key pair
  xnode bbr                      enable BBR congestion control
  xnode version`)
}

func interactive() bool {
	return term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
}

func ensureRoot(cmd string) error {
	if !isElevated() {
		if langZH {
			return errors.New(elevationHintZH)
		}
		return fmt.Errorf("%s %s", cmd, elevationHint)
	}
	return nil
}

var errCancelled = errors.New("cancelled")
