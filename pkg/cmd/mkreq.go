package cmd

import (
	"context"
	"io"
	"io/ioutil"
	"net/http"
	neturl "net/url"
	"os"
	"strings"
	"sync"

	"github.com/projectdiscovery/gologger"
	"github.com/schollz/progressbar/v3"

	"github.com/SpeedyQweku/qfuzz/pkg/common"
	"github.com/SpeedyQweku/qfuzz/pkg/config"
	"github.com/SpeedyQweku/qfuzz/pkg/opt"
)

// Declare and initialize a sync.Pool for http.Request objects and http.Response objects.
var (
	// requestPool is a pool of reusable http.Request objects.
	RequestPool = sync.Pool{
		// New defines a function that creates a new http.Request object.
		New: func() interface{} {
			return new(http.Request)
		},
	}

	// responsePool is a pool of reusable http.Response objects.
	ResponsePool = sync.Pool{
		// New defines a function that creates a new http.Response object.
		New: func() interface{} {
			return new(http.Response)
		},
	}
)

// Making http request func
func MakeRequest(url, word string, wg *sync.WaitGroup, semaphore chan struct{}, ctx context.Context, cfg config.Config, bar *progressbar.ProgressBar) {
	defer func() {
		<-semaphore // release semaphore
		wg.Done()
		bar.Add(1)
	}()

	var result config.Result
	fullURL := opt.ProcessUrls(url, word, cfg)
	cfg.PostData = strings.Replace(cfg.PostData, "FUZZ", word, 1)

	headers := make([]string, len(cfg.Headers))
	copy(headers, cfg.Headers)
	if opt.CheckFUZZheader(cfg.Headers) {
		for i, item := range headers {
			headers[i] = strings.Replace(item, "FUZZ", word, 1)
		}
	}

	// Reuse http.Request and http.Response using sync.Pool
	request := AcquireRequest()
	defer ReleaseRequest(request)
	request.URL, _ = neturl.Parse(fullURL)

	// Set the HTTP method
	if cfg.HttpMethod != "" {
		request.Method = strings.ToUpper(cfg.HttpMethod)
	} else {
		request.Method = "GET"
	}

	// Set User-Agent in the request header
	if request.Header == nil {
		request.Header = make(http.Header)
	}
	if len(headers) != 0 {
		for _, pair := range headers {
			parts := strings.SplitN(pair, ":", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])
				request.Header.Set(key, value)
			}
		}

		// Check if "User-Agent" header is present, and if not, add it
		if cfg.RandomUserAgent {
			if _, exists := request.Header["User-Agent"]; !exists {
				request.Header.Set("User-Agent", GetRandomUserAgent())
			}
		}
	} else if len(headers) == 0 && cfg.RandomUserAgent {
		request.Header.Set("User-Agent", GetRandomUserAgent())
	}

	// If PostData is provided, include it in the request body
	if cfg.PostData != "" {
		request.Body = ioutil.NopCloser(strings.NewReader(cfg.PostData))
		request.GetBody = func() (io.ReadCloser, error) {
			return ioutil.NopCloser(strings.NewReader(cfg.PostData)), nil
		}

		// Check if "Content-Type" header is present, and if not, add it
		if _, exists := request.Header["Content-Type"]; !exists {
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	}

	//Test func call
	// printFullRequest(request)

	response := AcquireResponse()
	defer ReleaseResponse(response)

	// Optionally wait for a user interrupt To exit gracefully
	select {
	case <-ctx.Done():
		// Context canceled, exit gracefully
		// bar.Finish()
		os.Exit(0)
		return
	default:
	}

	// Make the HTTP request
	resp, err := config.HttpClient.Do(request.WithContext(ctx))
	if err != nil {
		common.DebugModeEr(cfg.Debug, fullURL, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		RateLimit(fullURL, resp.StatusCode, request)
	}

	// var bodyBuffer bytes.Buffer
	// _, err = io.Copy(&bodyBuffer, resp.Body)
	// if err != nil {
	// 	debugModeEr(cfg.Debug, fullURL, err)
	// 	// return nil, err
	// }
	bodyBuffer, err := opt.ReadResponseBody(resp, fullURL)
	if err != nil {
		common.DebugModeEr(cfg.Debug, fullURL, err)
	}

	if len(cfg.MatchStrings) != 0 || len(cfg.FilterStrings) != 0 {
		result.Match = opt.DetectBodyMatch(fullURL, []byte(bodyBuffer))
	}

	result.StatusCode = resp.StatusCode
	result.Status = resp.Status
	result.URL = fullURL

	if resp.ContentLength != -1 {
		result.ContentSize = resp.ContentLength
	} else {
		bodyBytes := bodyBuffer
		result.ContentSize = int64(len(bodyBytes))
	}

	if cfg.WebCache {
		for key, val := range resp.Header {
			if opt.DetectWebCache(key, val, fullURL, &config.Mu) {
				break
			}
		}
	}

	// Process the result
	opt.ProcessResult(&result, cfg)
}

// http request just for web cache
func WebCacheRequest(url string, wg *sync.WaitGroup, semaphore chan struct{}, ctx context.Context, cfg config.Config, bar *progressbar.ProgressBar) {
	defer func() {
		<-semaphore // release semaphore
		wg.Done()
		bar.Add(1)
	}()

	var fullURL string
	var result config.Result

	urls, err := neturl.Parse(url)
	if err != nil {
		gologger.Error().Msgf(config.Red + "Invalid URL: " + url + config.Reset)
		return
	}
	if urls.Scheme == "" {
		urls.Scheme = "https"
	}

	fullURL = urls.String()

	// Reuse http.Request and http.Response using sync.Pool
	request := AcquireRequest()
	defer ReleaseRequest(request)
	request.URL, _ = neturl.Parse(fullURL)

	// Set the HTTP method
	if cfg.HttpMethod != "" {
		request.Method = strings.ToUpper(cfg.HttpMethod)
	} else {
		request.Method = "GET"
	}

	// Set User-Agent in the request header
	if request.Header == nil {
		request.Header = make(http.Header)
	}

	if len(cfg.Headers) != 0 {
		for _, pair := range cfg.Headers {
			parts := strings.SplitN(pair, ":", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])
				request.Header.Set(key, value)
			}
		}

		// Check if "User-Agent" header is present, and if not, add it
		if cfg.RandomUserAgent {
			if _, exists := request.Header["User-Agent"]; !exists {
				request.Header.Set("User-Agent", GetRandomUserAgent())
			}
		}
	} else if len(cfg.Headers) == 0 && cfg.RandomUserAgent {
		request.Header.Set("User-Agent", GetRandomUserAgent())
	}

	// If PostData is provided, include it in the request body
	if cfg.PostData != "" {
		request.Body = ioutil.NopCloser(strings.NewReader(cfg.PostData))
		request.GetBody = func() (io.ReadCloser, error) {
			return ioutil.NopCloser(strings.NewReader(cfg.PostData)), nil
		}

		// Check if "Content-Type" header is present, and if not, add it
		if _, exists := request.Header["Content-Type"]; !exists {
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	}

	response := AcquireResponse()
	defer ReleaseResponse(response)

	// Optionally wait for a user interrupt To exit gracefully
	select {
	case <-ctx.Done():
		// Context canceled, exit gracefully
		// bar.Finish()
		os.Exit(0)
		return
	default:
	}

	// Make the HTTP request
	resp, err := config.HttpClient.Do(request.WithContext(ctx))
	if err != nil {
		common.DebugModeEr(cfg.Debug, fullURL, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		RateLimit(fullURL, resp.StatusCode, request)
	}

	bodyBuffer, err := opt.ReadResponseBody(resp, fullURL)
	if err != nil {
		common.DebugModeEr(cfg.Debug, fullURL, err)
	}

	if len(cfg.MatchStrings) != 0 || len(cfg.FilterStrings) != 0 {
		result.Match = opt.DetectBodyMatch(fullURL, []byte(bodyBuffer))
	}

	if cfg.WebCache {
		if resp.StatusCode == http.StatusTooManyRequests {
			RateLimit(fullURL, resp.StatusCode, request)
		}
		for key, val := range resp.Header {
			if opt.DetectWebCache(key, val, fullURL, &config.Mu) {

				result.StatusCode = resp.StatusCode
				result.Status = resp.Status
				result.URL = fullURL

				if resp.ContentLength != -1 {
					result.ContentSize = resp.ContentLength
				} else {
					bodyBytes := bodyBuffer
					result.ContentSize = int64(len(bodyBytes))
				}

				// Process the result
				opt.ProcessResult(&result, cfg)
				break
			}
		}
	}
}
