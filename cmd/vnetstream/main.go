package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"v-netstream/internal/capture"
	"v-netstream/internal/monitor"
)

func main() {
	fmt.Println("V-NetStream initializing...")

	if os.Geteuid() != 0 {
		log.Fatal("This program must be run as root (or with sudo)")
	}

	interface := flag.String("i", "", "Interface to monitor")
	flag.Parse()

	if *interface == "" {
		log.Fatal("Please specify an interface to monitor with -i")
	}

	// Initialize TLS monitor
	mon, err := monitor.NewMonitor()
	if err != nil {
		log.Fatalf("Failed to create TLS monitor: %v", err)
	}
	defer mon.Close()

	if err := mon.Start(*interface); err != nil {
		log.Fatalf("Failed to start TLS monitor: %v", err)
	}

	// Initialize packet capture
	cap := capture.NewCapturer()
	if err := cap.Start(*interface); err != nil {
		log.Fatalf("Failed to start capturer: %v", err)
	}
	defer cap.Stop()

	// Handle TLS events
	go func() {
		for event := range mon.Events() {
			log.Printf("TLS Event: type=%d, version=0x%04x", 
				event.ContentType, event.Version)
		}
	}()

	// Handle packet info
	go func() {
		for packetInfo := range cap.GetPacketInfoChan() {
			fmt.Printf("Packet: %s:%d -> %s:%d\n",
				packetInfo.SrcIP, packetInfo.SrcPort,
				packetInfo.DstIP, packetInfo.DstPort)
		}
	}()

	// Wait for interrupt
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	fmt.Println("\nShutting down...")
}
