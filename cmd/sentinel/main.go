package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/0x0034/sentinel/internal/app"
	"github.com/0x0034/sentinel/internal/config"
	"github.com/0x0034/sentinel/internal/feed"
	"github.com/0x0034/sentinel/internal/notify"
	"github.com/0x0034/sentinel/internal/store"
)

var version = "dev"

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(log); err != nil {
		log.Error("sentinel stopped", "error", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	command := "run"
	args := os.Args[1:]
	if len(args) > 0 && len(args[0]) > 0 && args[0][0] != '-' {
		command = args[0]
		args = args[1:]
	}
	if command == "version" {
		fmt.Printf("sentinel %s %s %s/%s\n", version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
		return nil
	}
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	path := flags.String("config", "config.yaml", "configuration file")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected command arguments")
	}
	if command != "run" && command != "once" && command != "check" && command != "send-test" {
		return errors.New("commands: run, once, check, send-test, version")
	}
	cfg, err := config.Load(*path)
	if err != nil {
		return err
	}
	if command == "check" {
		log.Info("configuration valid", "subscriptions", len(cfg.Subscriptions))
		return nil
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	sender := notify.NewClient()
	if command == "send-test" {
		for _, sub := range cfg.Subscriptions {
			now := time.Now()
			notices := app.TestNotices(now, cfg.Location)
			incremental, err := notify.Incremental("【测试】"+sub.Name, notices[0], cfg.Location)
			if err != nil {
				return err
			}
			if err := sender.Send(ctx, sub.Webhook, incremental); err != nil {
				return err
			}
			payloads, err := notify.Digest("【测试】"+sub.Name, notices[0].PublishedAt.In(cfg.Location).Format("2006-01-02"), notices, cfg.Location, false)
			if err != nil {
				return err
			}
			for _, payload := range payloads {
				if err := sender.Send(ctx, sub.Webhook, payload); err != nil {
					return err
				}
			}
			log.Info("test incremental and digest delivered", "subscription", sub.ID)
		}
		return nil
	}
	db, err := store.Open(cfg.Database)
	if err != nil {
		return err
	}
	defer db.Close()
	service := app.New(cfg, db, feed.NewClient(), sender, log)
	if command == "once" {
		return service.Once(ctx, time.Now())
	}
	log.Info("sentinel started", "version", version, "go", runtime.Version(), "subscriptions", len(cfg.Subscriptions))
	return service.Run(ctx)
}
