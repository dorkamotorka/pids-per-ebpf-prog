package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go observe observe.c

import (
	"log"
	"time"
	"bufio"

	"github.com/cilium/ebpf/rlimit"
	"github.com/cilium/ebpf/link"
)

func main() {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock limit: %v", err)
	}

	// Load pre-compiled eBPF program into the kernel.
	objs := observeObjects{}
	if err := loadObserveObjects(&objs, nil); err != nil {
		log.Fatalf("Failed to load objects: %v", err)
	}
	defer objs.Close()

	// Attach the program to the desired hook.
	iterLink, err := link.AttachIter(link.IterOptions{
		Program: objs.DumpTaskFile,
	})
	if err != nil {
		log.Fatalf("Failed to attach eBPF program: %v", err)
	}
	defer iterLink.Close()
	log.Println("eBPF program attached successfully.")


	// Keep the program running.
	for {
		time.Sleep(1 * time.Second)
		reader, err := iterLink.Open()
		if err != nil {
			log.Fatal("failed to open BPF iterator: %w", err)
		}
		defer reader.Close()

		scanner := bufio.NewScanner(reader)
		for scanner.Scan() {
			log.Printf(scanner.Text())
		}
	}
}

