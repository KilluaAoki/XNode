package cmd

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/KilluaAoki/XNode/common/nlog"
	"github.com/KilluaAoki/XNode/conf"
	"github.com/KilluaAoki/XNode/node"
)

var stopRequests = make(chan os.Signal, 1)

func requestStop() {
	select {
	case stopRequests <- syscall.SIGTERM:
	default:
	}
}

func runServer(args []string) error {
	if ok, err := runAsService(func() error { return serve(args) }); ok {
		return err
	}
	return serve(args)
}

func serve(args []string) error {
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	configPath := fs.String("c", "config.yml", "config file path")
	envFile := fs.String("e", "", "environment file path")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if err := conf.LoadEnvFile(*envFile); err != nil {
		return fmt.Errorf("failed to load env file: %w", err)
	}

	rootCfg, err := conf.LoadRoot(*configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	instances, err := rootCfg.NormalizeInstances()
	if err != nil {
		return fmt.Errorf("failed to normalize config: %w", err)
	}
	conf.InitLogger(instances[0].Log)
	nlog.Core().Info("starting", "version", version)
	if backup, err := conf.MigrateConfigFile(*configPath); err != nil {
		nlog.Core().Warn("failed to migrate config file to the nodes list", "path", *configPath, "error", err)
	} else if backup != "" {
		nlog.Core().Info("migrated config file to the nodes list", "path", *configPath, "backup", backup)
	}

	runWithReload(rootCfg, *configPath)
	return nil
}

func runWithReload(initialRoot *conf.RootConfig, configPath string) {
	var healthSrv *http.Server
	var healthPort int
	startHealth := func(port int) {
		if port <= 0 {
			return
		}
		ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
		if err != nil {
			nlog.Core().Error("failed to start health check listener", "port", port, "error", err)
			os.Exit(1)
		}
		mux := http.NewServeMux()
		mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"ok"}`))
		})
		healthSrv = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
		healthPort = port
		go func() {
			nlog.Core().Debug(fmt.Sprintf("health check listening on :%d", port))
			if err := healthSrv.Serve(ln); err != nil && err != http.ErrServerClosed {
				nlog.Core().Warn("health check server stopped", "error", err)
			}
		}()
	}

	initialInstances, err := initialRoot.NormalizeInstances()
	if err != nil {
		nlog.Core().Error("failed to normalize initial config", "error", err)
		os.Exit(1)
	}
	startHealth(initialInstances[0].HealthPort)
	defer func() {
		if healthSrv != nil {
			healthSrv.Close()
		}
	}()

	for root := initialRoot; ; {
		ctx, cancel := context.WithCancel(context.Background())

		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

		reloadCh := make(chan *conf.RootConfig, 1)

		watcher, err := conf.WatchConfigRoot(ctx, configPath, func(newCfg *conf.RootConfig) {
			select {
			case reloadCh <- newCfg:
			default:
			}
		})
		if err != nil {
			nlog.Core().Warn("config watcher unavailable, hot-reload disabled", "error", err)
		}

		go func() {
			var sig os.Signal
			select {
			case sig = <-sigCh:
			case sig = <-stopRequests:
			case <-ctx.Done():
				return
			}
			nlog.Core().Info(fmt.Sprintf("received %v, shutting down...", sig))
			cancel()

			select {
			case sig = <-sigCh:
			case sig = <-stopRequests:
			case <-time.After(15 * time.Second):
				nlog.Core().Error("shutdown timed out after 15s, forcing exit")
				os.Exit(2)
			}
			nlog.Core().Warn("received second signal, forcing exit", "signal", sig)
			os.Exit(1)
		}()

		instances, err := root.NormalizeInstances()
		if err != nil {
			nlog.Core().Error("failed to normalize config", "error", err)
			os.Exit(1)
		}
		if err := conf.ValidateStartupLayout(instances); err != nil {
			nlog.Core().Error("startup layout validation failed", "error", err)
			os.Exit(1)
		}

		if instances[0].HealthPort != healthPort {
			if healthSrv != nil {
				healthSrv.Close()
				healthSrv = nil
			}
			startHealth(instances[0].HealthPort)
		}

		errCh := make(chan error, len(instances))
		doneCh := make(chan struct{})
		var wg sync.WaitGroup
		for _, instanceCfg := range instances {
			instanceCfg := instanceCfg
			wg.Add(1)
			go func() {
				defer wg.Done()
				if instanceCfg.IsMachineMode() {
					nlog.Core().Info("starting machine instance", "instance", instanceCfg.InstanceID, "machine_id", instanceCfg.Machine.MachineID, "panel_url", instanceCfg.Panel.URL)
					orch := node.NewOrchestrator(instanceCfg)
					if err := orch.Run(ctx); err != nil {
						nlog.Core().Error("machine instance exited with error", "instance", instanceCfg.InstanceID, "error", err)
						errCh <- err
						cancel()
					}
					return
				}
				nodes := instanceCfg.ExpandNodes()
				nlog.Core().Info("starting node instance", "instance", instanceCfg.InstanceID, "nodes", len(nodes), "panel_url", instanceCfg.Panel.URL)
				var instanceWG sync.WaitGroup
				for idx, nodeCfg := range nodes {
					nodeCfg := nodeCfg
					instanceWG.Add(1)
					go func(idx int) {
						defer instanceWG.Done()
						if idx > 0 {
							delay := time.Duration(idx) * 250 * time.Millisecond
							if delay > 2*time.Second {
								delay = 2 * time.Second
							}
							select {
							case <-time.After(delay):
							case <-ctx.Done():
								return
							}
						}
						svc := node.New(nodeCfg)
						if err := svc.Run(ctx); err != nil {
							nlog.Core().Error("node service exited with error", "instance", nodeCfg.InstanceID, "node_id", nodeCfg.Panel.NodeID, "error", err)
							errCh <- err
							cancel()
						}
					}(idx)
				}
				instanceWG.Wait()
			}()
		}
		go func() { wg.Wait(); close(doneCh) }()

		var newRoot *conf.RootConfig
		select {
		case newRoot = <-reloadCh:
			nlog.Core().Info("config changed, restarting all services...")
			cancel()
			<-doneCh
		case <-doneCh:
		}

		signal.Stop(sigCh)
		if watcher != nil {
			watcher.Stop()
		}

		if newRoot == nil {
			close(errCh)
			if err := <-errCh; err != nil {
				os.Exit(1)
			}
			nlog.Core().Info("stopped")
			return
		}

		newInstances, err := newRoot.NormalizeInstances()
		if err != nil {
			nlog.Core().Error("failed to normalize reloaded config", "error", err)
			os.Exit(1)
		}
		conf.InitLogger(newInstances[0].Log)
		root = newRoot
		nlog.Core().Info("reload complete, services restarting with new config")
	}
}
