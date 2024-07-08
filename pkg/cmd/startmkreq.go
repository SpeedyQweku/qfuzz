package cmd

import (
	"context"
	"sync"

	"github.com/schollz/progressbar/v3"

	"github.com/SpeedyQweku/qfuzz/pkg/config"
)


// startRequests starts the HTTP requests using goroutines
func StartRequests(ctx context.Context, wg *sync.WaitGroup, semaphore chan struct{}, bar *progressbar.ProgressBar, words, urls []string) {
	if config.Cfg.WebCache && config.Cfg.WordlistFile == "" {
		for _, url := range urls {
			wg.Add(1)               // Increment the wait group counter
			semaphore <- struct{}{} // acquire semaphore
			go WebCacheRequest(url, wg, semaphore, ctx, config.Cfg, bar)
		}
	} else {
		for _, word := range words {
			for _, url := range urls {
				wg.Add(1)               // Increment the wait group counter
				semaphore <- struct{}{} // acquire semaphore
				go MakeRequest(url, word, wg, semaphore, ctx, config.Cfg, bar)
			}
		}
	}
}
