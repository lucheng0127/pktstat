package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	pktstat "github.com/lucheng0127/pkgstat"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"
)

var shutdownSignals = []os.Signal{os.Interrupt, syscall.SIGTERM}

func SetupSignalHandler() context.Context {
	ctx, cancel := context.WithCancel(context.Background())

	c := make(chan os.Signal, 2)
	signal.Notify(c, shutdownSignals...)
	go func() {
		<-c
		cancel()
		<-c
		os.Exit(1) // second signal. Exit directly.
	}()

	return ctx
}

func launch(ctx context.Context, cmd *cli.Command) error {
	// Start capture and processing here
	log.Info("Starting packet capture...")

	statCh := make(chan pktstat.StatChKey, 1000)
	defer close(statCh)

	statHandler := pktstat.NewStatHandler(ctx, statCh)

	statMap := make(pktstat.StatMap)
	go func() {
		for k := range statCh {
			entry, ok := statMap[k.Key]
			if !ok {
				entry = pktstat.StatEntry{}
			}

			entry.Packets++
			entry.Bytes += int64(k.Size)
			statMap[k.Key] = entry
		}
	}()

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(10 * time.Second):
				log.Info("Current statistics:")
				for k, v := range statMap {
					log.Infof("%s:%d -> %s:%d [%s] - Packets: %d, Bytes: %d",
						k.SrcIP, k.SrcPort, k.DstIP, k.DstPort, k.Proto, v.Packets, v.Bytes)
				}
			}
		}
	}()

	if err := pktstat.CaptureAndHandle(
		cmd.String("interface"),
		"",
		cmd.Int32("snaplen"),
		statHandler); err != nil {
		return err
	}

	// Wait for shutdown signal
	<-ctx.Done()
	log.Info("Shutting down...")

	// Clenup
	return nil
}

func main() {
	ctx := SetupSignalHandler()

	cmd := &cli.Command{
		Name:   "pktstat",
		Usage:  "Packet statistics tool",
		Action: launch,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "interface",
				Aliases:  []string{"i"},
				Usage:    "Network interface to capture packets from",
				Required: true,
			},
			&cli.Int32Flag{
				Name:    "snaplen",
				Aliases: []string{"s"},
				Value:   65535,
				Usage:   "Snap length for packet capture",
			},
		},
	}

	if err := cmd.Run(ctx, os.Args); err != nil {
		log.Error(err)
		os.Exit(1)
	}
}
