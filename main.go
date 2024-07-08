package main

import (
	"fmt"
	"context"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/schollz/progressbar/v3"
	"github.com/projectdiscovery/gologger"

	"github.com/SpeedyQweku/qfuzz/pkg/parser"
	"github.com/SpeedyQweku/qfuzz/pkg/opt"
	"github.com/SpeedyQweku/qfuzz/pkg/config"
	"github.com/SpeedyQweku/qfuzz/pkg/mkreq"
)


func init() {
	parser.Parse()
	config.UserAgents()
}

// The main func
func main() {
	// Check if no arguments are provided (excluding the program name)
	if len(os.Args) == 1 {
		gologger.Info().Msgf("No arguments provided.[-h/--help for help]")
		os.Exit(0)
	}

	// Create a context with cancellation ability
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // Ensure the context is canceled when main function exits

	// Set up signal handling
	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, os.Interrupt, syscall.SIGTERM)

	// Start a goroutine To listen for signals and cancel the context on signal
	go func() {
		select {
		case sig := <-signalCh:
			fmt.Println("\r\033[K")
			fmt.Printf("[WARN] Caught keyboard: %v (Ctrl-C)\n", sig)
			fmt.Println("\r\033[K")
			cancel()
		case <-ctx.Done():
			// Context canceled, no need To handle signals
		}
	}()

	// Validate and process configurations
	opt.ValidateConfig()

	if !config.Cfg.FollowRedirect {
		config.HttpClient.CheckRedirect = nil
	}

	// Read wordlist and URLs
	words, urls := opt.ReadInputFiles(config.Cfg)

	if config.Cfg.OutputFile != "" {
		file, err := os.Create(config.Cfg.OutputFile)
		if err != nil {
			gologger.Fatal().Msgf("Error creating success file: %v", err)
		}
		defer file.Close()
		config.Cfg.SuccessFile = file
	}

	// Use a WaitGroup To wait for all goroutines To finish
	var wg sync.WaitGroup

	// Define a progress bar pointer
	var bar *progressbar.ProgressBar
	if config.Cfg.WebCache && config.Cfg.WordlistFile == "" {
		bar = opt.Progbar(len(urls))
	} else {
		bar = opt.Progbar(len(words) * len(urls))
	}

	// Create a semaphore To limit concurrency
	semaphore := make(chan struct{}, config.Cfg.Concurrency)

	// Start the requests
	mkreq.StartRequests(ctx, &wg, semaphore, bar, words, urls)

	// Start a goroutine To close the results channel once all requests are done
	go func() {
		wg.Wait()
		close(semaphore)
	}()

	// Optionally wait for a user interrupt To exit gracefully
	select {
	case <-ctx.Done():
		// Context canceled, exit gracefully
		bar.Finish()
		return
	default:
	}

	bar.Finish()
}
