package mkreq

import (
	"errors"
	"net/http"
	"time"

	"golang.org/x/exp/rand"

	"github.com/SpeedyQweku/qfuzz/pkg/common"
	"github.com/SpeedyQweku/qfuzz/pkg/config"
)


// Helper function to acquire and release request
func AcquireRequest() *http.Request {
	return RequestPool.Get().(*http.Request)
}

// Helper function to acquire and release request
func ReleaseRequest(req *http.Request) {
	req.URL = nil
	req.Body = nil
	req.Header = nil
	RequestPool.Put(req)
}

// Helper function to acquire and release response
func AcquireResponse() *http.Response {
	return ResponsePool.Get().(*http.Response)
}

// Helper function to acquire and release response
func ReleaseResponse(resp *http.Response) {
	ResponsePool.Put(resp)
}

// Select a random User-Agent from the list
func GetRandomUserAgent() string {
	// panic(len(config.Cfg.UserAgents))
	return config.Cfg.UserAgents[rand.Intn(len(config.Cfg.UserAgents))]
}

// rate limit for the http request
func RateLimit(fullURL string, sCode int, request *http.Request) {
	retryAttempts := 0
	maxRetries := config.Cfg.Retries
	for retryAttempts < maxRetries {
		retryAttempts++
		// Exponential backoff: wait for 2^retryAttempts seconds before retrying
		backoffDuration := time.Duration(2<<retryAttempts+1) * time.Second
		// log.Printf(Yellow+"Received 429 Too Many Requests. Retrying in %v seconds..."+Reset, backoffDuration.Seconds())
		time.Sleep(backoffDuration)
		// config.Cfg.httpClient To httpClient
		resp, err := config.HttpClient.Do(request)
		if err != nil {
			common.DebugModeEr(config.Cfg.Debug, fullURL, err)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusTooManyRequests {
			break
		}
	}
	if sCode == http.StatusTooManyRequests {
		common.DebugModeEr(config.Cfg.Debug, fullURL, errors.New("429 TooManyRequests"))
		return
	}
}
