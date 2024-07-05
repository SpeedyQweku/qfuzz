package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"

	// "reflect"
	"context"
	"crypto/tls"
	"math/rand"
	"net"
	"net/http"
	neturl "net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/schollz/progressbar/v3"
	"golang.org/x/net/html"
)

const (
	version = "v0.2.5"
	Reset   = "\033[0m"
	Red     = "\033[31m"
	Blue    = "\033[34m"
	Yellow  = "\033[33m"
	Cyan    = "\033[36m"
	Green   = "\033[32m"
	White   = "\033[37m"
	Banner  = White + ` 
	 ██████╗ ███████╗██╗   ██╗███████╗███████╗
	██╔═══██╗██╔════╝██║   ██║╚══███╔╝╚══███╔╝
	██║   ██║█████╗  ██║   ██║  ███╔╝   ███╔╝ 
	██║▄▄ ██║██╔══╝  ██║   ██║ ███╔╝   ███╔╝  
	╚██████╔╝██║     ╚██████╔╝███████╗███████╗
	 ╚══▀▀═╝ ╚═╝      ╚═════╝ ╚══════╝╚══════╝
` + Reset
)

// Result represents the result of an HTTP request.
type Result struct {
	StatusCode  int    // StatusCode is the HTTP status code returned by the server (e.g., 200, 404).
	Status      string // Status is the HTTP status message returned by the server (e.g., "200 OK", "404 Not Found").
	ContentSize int64  // ContentSize is the size of the response content in bytes.
	URL         string // URL is the URL that was requested.
	Match       bool   // Match indicates whether the response matched certain criteria (specific strings).
}

// Config holds configuration settings for the application.
type Config struct {
	OutputFile        string              // OutputFile specifies the path to the file where output will be written.
	WordlistFile      string              // WordlistFile specifies the path to the file containing a list of words.
	UrlFile           string              // UrlFile specifies the path to the file containing a list of URLs.
	PostData          string              // PostData contains the data to be sent in a POST request.
	HttpMethod        string              // HttpMethod specifies the HTTP method to use (e.g., GET, POST).
	UserAgents        []string            // UserAgents is a list of user agent strings to use for requests.
	FollowRedirect    bool                // FollowRedirect indicates whether redirects should be followed.
	Silent            bool                // Silent controls whether output should be minimized.
	RandomUserAgent   bool                // RandomUserAgent indicates whether a random user agent should be used for each request.
	Debug             bool                // Debug enables debug mode, providing more detailed logging.
	Http2             bool                // Http2 enables the use of HTTP/2 for requests.
	WebCache          bool                // WebCache enables the use of web caching detection.
	To                int                 // To specifies the timeout for HTTP requests, in seconds.
	Concurrency       int                 // Concurrency specifies the number of concurrent requests to make.
	Retries           int                 // Retries specifies the number of times to retry failed requests.
	SuccessFile       *os.File            // SuccessFile is a file handle to write successful requests to.
	Cachefile         *os.File            // Cachefile is a file handle to write successful web caching detection.
	UrlString         goflags.StringSlice // UrlString is a slice of URL strings specified.
	Headers           goflags.StringSlice // Headers is a slice of HTTP headers specified.
	MatchStrings      goflags.StringSlice // MatchStrings is a slice of strings to match in responses.
	MatchStatus       goflags.StringSlice // MatchStatus is a slice of HTTP status codes to match in responses status code.
	MatchContentSize  goflags.StringSlice // MatchContentSize is a slice of ContentSize to match in Content-Length.
	FilterStrings     goflags.StringSlice // FilterStrings is a slice of strings to filter out in responses.
	FilterStatus      goflags.StringSlice // FilterStatus is a slice of HTTP status codes to filter out in responses status code.
	FilterContentSize goflags.StringSlice // FilterContentSize is a slice of ContentSize to filter out in Content-Length.
}

// Declare and initialize a sync.Pool for http.Request objects and http.Response objects.
var (
	// requestPool is a pool of reusable http.Request objects.
	requestPool = sync.Pool{
		// New defines a function that creates a new http.Request object.
		New: func() interface{} {
			return new(http.Request)
		},
	}

	// responsePool is a pool of reusable http.Response objects.
	responsePool = sync.Pool{
		// New defines a function that creates a new http.Response object.
		New: func() interface{} {
			return new(http.Response)
		},
	}

	cfg Config
	mu  sync.Mutex
)

func init() {
	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription("qfuzz, fuzz and more - " + version)
	flagSet.CreateGroup("input", "INPUT OPTIONS",
		flagSet.StringVarP(&cfg.WordlistFile, "w", "wordlist", "", "Wordlist file path"),
		flagSet.StringVarP(&cfg.UrlFile, "l", "list", "", "Target file path"),
		flagSet.StringSliceVar(&cfg.UrlString, "u", nil, "Target URL(s) (-u https://example.com,https://example.org)", goflags.CommaSeparatedStringSliceOptions),
	)
	flagSet.CreateGroup("output", "OUTPUT OPTIONS",
		flagSet.StringVarP(&cfg.OutputFile, "o", "output", "", "Output file path"),
	)
	flagSet.CreateGroup("matchers", "MATCHERS OPTIONS",
		flagSet.StringSliceVar(&cfg.MatchStatus, "mc", nil, "Match HTTP status code(s), (default 200-299,301,302,307,401,403,405,500)", goflags.CommaSeparatedStringSliceOptions),
		flagSet.StringSliceVar(&cfg.MatchStrings, "ms", nil, "Match response body with specified string(s) (-ms example,string)", goflags.CommaSeparatedStringSliceOptions),
		flagSet.StringSliceVar(&cfg.MatchContentSize, "ml", nil, "Match HTTP response size", goflags.CommaSeparatedStringSliceOptions),
	)
	flagSet.CreateGroup("Filter", "FILTER OPTIONS",
		flagSet.StringSliceVar(&cfg.FilterStatus, "fc", nil, "Filter HTTP status code(s). eg (-fc 500,202)", goflags.CommaSeparatedStringSliceOptions),
		flagSet.StringSliceVar(&cfg.FilterStrings, "fs", nil, "Filter response body with specified string(s). eg (-fs example,string)", goflags.CommaSeparatedStringSliceOptions),
		flagSet.StringSliceVar(&cfg.FilterContentSize, "fl", nil, "Filter HTTP response size. eg (-fl 4343,433)", goflags.CommaSeparatedStringSliceOptions),
	)
	flagSet.CreateGroup("configurations ", "CONFIGURATIONS OPTIONS",
		flagSet.StringVar(&cfg.HttpMethod, "X", "", "HTTP method To use in the request, (e.g., GET, POST, PUT, DELETE)"),
		flagSet.StringVarP(&cfg.PostData, "d", "data", "", "Data To include in the request body for POST method"),
		flagSet.StringSliceVar(&cfg.Headers, "H", nil, "Headers To include in the request, (e.g., 'key1:value1,key2:value2')", goflags.CommaSeparatedStringSliceOptions),
		flagSet.BoolVarP(&cfg.FollowRedirect, "fr", "follow-redirects", false, "Follow redirects"),
		flagSet.BoolVar(&cfg.WebCache, "webcache", false, "Detect web caching, (discoveredWebCache.txt)"),
		flagSet.BoolVarP(&cfg.RandomUserAgent, "random-agent", "ra", false, "Enable Random User-Agent To use"),
		flagSet.IntVar(&cfg.Retries, "retries", 5, "number of Retries, if status code is 429"),
		flagSet.BoolVar(&cfg.Http2, "http2", false, "use HTTP2 protocol"),
	)
	flagSet.CreateGroup("optimizations", "OPTIMIZATIONS OPTIONS",
		flagSet.IntVar(&cfg.Concurrency, "c", 40, "number of concurrency To use"),
		flagSet.IntVarP(&cfg.To, "to", "timeout", 10, "timeout (seconds)"),
	)
	flagSet.CreateGroup("debug", "DEBUG OPTIONS",
		flagSet.BoolVar(&cfg.Silent, "silent", false, "Silent mode"),
		flagSet.BoolVar(&cfg.Debug, "debug", false, "Debug mode"),
	)

	_ = flagSet.Parse()

	// User-Agent list
	cfg.UserAgents = []string{
		"Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.157 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.9; rv:36.0) Gecko/20100101 Firefox/36.0",
		"Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; InfoPath.3; .NET4.0C; .NET4.0E)",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
		"Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko",
		"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.100 Safari/537.36",
		"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36",
		"Mozilla/5.0 (Linux; U; Android 4.0.3; en-ca; KFOT Build/IML74K) AppleWebKit/537.36 (KHTML, like Gecko) Silk/3.68 like Chrome/39.0.2171.93 Safari/537.36",
		"Mozilla/5.0 (Linux; Android 4.2.2; Le Pan TC802A Build/JDQ39) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.84 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_4) AppleWebKit/603.1.30 (KHTML, like Gecko) Version/10.1 Safari/603.1.30",
		"Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:73.0) Gecko/20100101 Firefox/73.0",
		"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:45.0) Gecko/20100101 Firefox/45.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:54.0) Gecko/20100101 Firefox/54.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36 Edge/16.16299",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.2987.133 Safari/537.36 Edge/16.16299",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.140 Safari/537.36 Edge/17.17134",
		"Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
		"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36",
		"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.141 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.182 Safari/537.36",
		"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.114 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.63 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.81 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.99 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.82 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.60 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4942.83 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.4987.69 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 14.1; rv:109.0) Gecko/20100101 Firefox/121.0",
		"Mozilla/5.0 (X11; Linux i686; rv:109.0) Gecko/20100101 Firefox/121.0",
		"Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/121.0",
		"Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:109.0) Gecko/20100101 Firefox/121.0",
		"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/121.0",
		"Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/121.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:115.0) Gecko/20100101 Firefox/115.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 14.1; rv:115.0) Gecko/20100101 Firefox/115.0",
		"Mozilla/5.0 (X11; Linux i686; rv:115.0) Gecko/20100101 Firefox/115.0",
		"Mozilla/5.0 (Linux x86_64; rv:115.0) Gecko/20100101 Firefox/115.0",
		"Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:115.0) Gecko/20100101 Firefox/115.0",
		"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:115.0) Gecko/20100101 Firefox/115.0",
		"Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:115.0) Gecko/20100101 Firefox/115.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.2210.91",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.2210.91",
	}
}

var httpClient = &http.Client{
	CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
	Timeout:       time.Duration(time.Duration(cfg.To) * time.Second),
	Transport: &http.Transport{
		ForceAttemptHTTP2:   cfg.Http2,
		MaxIdleConns:        1000,
		MaxIdleConnsPerHost: 500,
		MaxConnsPerHost:     500,
		IdleConnTimeout:     time.Duration(time.Duration(cfg.To) * time.Second),
		DisableKeepAlives:   false, // Enable connection reuse
		// DisableCompression:  true,
		DialContext: (&net.Dialer{
			Timeout: time.Duration(time.Duration(cfg.To) * time.Second),
		}).DialContext,
		TLSHandshakeTimeout: time.Duration(time.Duration(cfg.To) * time.Second),
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
			Renegotiation:      tls.RenegotiateOnceAsClient,
		},
	},
}

// Select a random User-Agent from the list
func getRandomUserAgent() string {
	return cfg.UserAgents[rand.Intn(len(cfg.UserAgents))]
}

// Helper function to acquire and release request
func acquireRequest() *http.Request {
	return requestPool.Get().(*http.Request)
}

// Helper function to acquire and release request
func releaseRequest(req *http.Request) {
	req.URL = nil
	req.Body = nil
	req.Header = nil
	requestPool.Put(req)
}

// Helper function to acquire and release response
func acquireResponse() *http.Response {
	return responsePool.Get().(*http.Response)
}

// Helper function to acquire and release response
func releaseResponse(resp *http.Response) {
	responsePool.Put(resp)
}

// debugModeEr print out all errors
func debugModeEr(debug bool, urlStr string, message error) {
	if debug {
		gologger.Error().Msgf("Error %s: %v", urlStr, message)
	}
}

// Reading A File Line By Line
func readLines(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	return lines, scanner.Err()
}

// check if "FUZZ" is in the headers
func headerFUZZcheck(headerData []string) bool {
	for _, item := range headerData {
		if strings.Contains(item, "FUZZ") {
			return true
		}
	}
	return false
}

// processUrls process the urls
func processUrls(url, word string, cfg Config) string {
	var fullURL string

	urls, err := neturl.Parse(url)
	if err != nil {
		gologger.Error().Msgf(Red + "Invalid URL: " + url + Reset)
		// return
	}
	if urls.Scheme == "" {
		urls.Scheme = "https"
	}

	if strings.HasPrefix(word, "/") {
		word = strings.TrimLeft(word, "/")
	}

	if strings.Contains(cfg.PostData, "FUZZ") || headerFUZZcheck(cfg.Headers) {
		// fmt.Println(cfg.PostData)
		fullURL = urls.String()
		// } else if headerFUZZcheck(cfg.Headers) {
		// 	// fmt.Println(header)
		// 	fullURL = urls.String()
	} else if strings.Contains(urls.String(), "FUZZ") {
		fullURL = strings.Replace(urls.String(), "FUZZ", word, 1)
	} else if strings.HasSuffix(urls.String(), "/") {
		urlstr := strings.TrimRight(urls.String(), "/")
		fullURL = fmt.Sprintf("%s/%s", urlstr, word)
	} else {
		fullURL = fmt.Sprintf("%s/%s", urls.String(), word)
	}
	return fullURL
}

// Making http request func
func makeRequest(url, word string, wg *sync.WaitGroup, semaphore chan struct{}, ctx context.Context, cfg Config, bar *progressbar.ProgressBar) {
	defer func() {
		<-semaphore // release semaphore
		wg.Done()
		bar.Add(1)
	}()

	var result Result
	fullURL := processUrls(url, word, cfg)
	cfg.PostData = strings.Replace(cfg.PostData, "FUZZ", word, 1)

	headers := make([]string, len(cfg.Headers))
	copy(headers, cfg.Headers)
	if headerFUZZcheck(cfg.Headers) {
		for i, item := range headers {
			headers[i] = strings.Replace(item, "FUZZ", word, 1)
		}
	}

	// Reuse http.Request and http.Response using sync.Pool
	request := acquireRequest()
	defer releaseRequest(request)
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
				request.Header.Set("User-Agent", getRandomUserAgent())
			}
		}
	} else if len(headers) == 0 && cfg.RandomUserAgent {
		request.Header.Set("User-Agent", getRandomUserAgent())
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

	response := acquireResponse()
	defer releaseResponse(response)

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
	resp, err := httpClient.Do(request.WithContext(ctx))
	if err != nil {
		debugModeEr(cfg.Debug, fullURL, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		rateLimit(fullURL, resp.StatusCode, request)
	}

	// var bodyBuffer bytes.Buffer
	// _, err = io.Copy(&bodyBuffer, resp.Body)
	// if err != nil {
	// 	debugModeEr(cfg.Debug, fullURL, err)
	// 	// return nil, err
	// }
	bodyBuffer, err := readResponseBody(resp, fullURL)
	if err != nil {
		debugModeEr(cfg.Debug, fullURL, err)
	}

	if len(cfg.MatchStrings) != 0 || len(cfg.FilterStrings) != 0 {
		result.Match = detectBodyMatch(fullURL, []byte(bodyBuffer))
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
			if detectWebCache(key, val, fullURL, &mu) {
				break
			}
		}
	}

	// Process the result
	processResult(&result, cfg)
}

// http request just for web cache
func webCacheRequest(url string, wg *sync.WaitGroup, semaphore chan struct{}, ctx context.Context, cfg Config, bar *progressbar.ProgressBar) {
	defer func() {
		<-semaphore // release semaphore
		wg.Done()
		bar.Add(1)
	}()

	var fullURL string
	var result Result

	urls, err := neturl.Parse(url)
	if err != nil {
		gologger.Error().Msgf(Red + "Invalid URL: " + url + Reset)
		return
	}
	if urls.Scheme == "" {
		urls.Scheme = "https"
	}

	fullURL = urls.String()

	// Reuse http.Request and http.Response using sync.Pool
	request := acquireRequest()
	defer releaseRequest(request)
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
				request.Header.Set("User-Agent", getRandomUserAgent())
			}
		}
	} else if len(cfg.Headers) == 0 && cfg.RandomUserAgent {
		request.Header.Set("User-Agent", getRandomUserAgent())
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

	response := acquireResponse()
	defer releaseResponse(response)

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
	resp, err := httpClient.Do(request.WithContext(ctx))
	if err != nil {
		debugModeEr(cfg.Debug, fullURL, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		rateLimit(fullURL, resp.StatusCode, request)
	}

	bodyBuffer, err := readResponseBody(resp, fullURL)
	if err != nil {
		debugModeEr(cfg.Debug, fullURL, err)
	}

	if len(cfg.MatchStrings) != 0 || len(cfg.FilterStrings) != 0 {
		result.Match = detectBodyMatch(fullURL, []byte(bodyBuffer))
	}

	if cfg.WebCache {
		if resp.StatusCode == http.StatusTooManyRequests {
			rateLimit(fullURL, resp.StatusCode, request)
		}
		for key, val := range resp.Header {
			if detectWebCache(key, val, fullURL, &mu) {

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
				processResult(&result, cfg)
				break
			}
		}
	}
}

// It reads the response body
func readResponseBody(resp *http.Response, fullUrl string) ([]byte, error) {
	var bodyBuffer bytes.Buffer
	_, err := io.Copy(&bodyBuffer, resp.Body)
	if err != nil {
		debugModeEr(cfg.Debug, fullUrl, err)
		return nil, err
	}
	return bodyBuffer.Bytes(), nil
}

// Check if the HTTP response has a specific string
func detectBodyMatch(fullURL string, body []byte) bool {
	bodyReader := bytes.NewReader(body)
	doc, err := html.Parse(bodyReader)
	if err != nil {
		debugModeEr(cfg.Debug, fullURL, err)
		return false
	}

	var responseText, title string
	var traverse func(*html.Node)
	traverse = func(n *html.Node) {
		if n.Type == html.TextNode {
			responseText += n.Data
		} else if n.Type == html.ElementNode && n.Data == "title" {
			if n.FirstChild != nil {
				title = n.FirstChild.Data
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			traverse(c)
		}
	}
	traverse(doc)
	if len(cfg.MatchStrings) != 0 {
		if matchRespData([]byte(responseText), cfg.MatchStrings) || matchRespData([]byte(title), cfg.MatchStrings) {
			return true
		}
	}
	if len(cfg.FilterStrings) != 0 {
		if matchRespData([]byte(responseText), cfg.FilterStrings) || matchRespData([]byte(title), cfg.FilterStrings) {
			return true
		}
	}
	return false
}

// detectWebCache identifies if the host is utilizing web caching, and if so, stores it.
func detectWebCache(key string, vals []string, fullURL string, mu *sync.Mutex) bool {
	var cacheHeaders = []string{"X-Cache", "Cf-Cache-Status", "Cache-Control", "Vary", "Age", "Server-Timing"}
	cacheFound := false // Track if cache is found

	for _, header := range cacheHeaders {
		if strings.EqualFold(key, header) {
			if key == "X-Cache" || key == "Cf-Cache-Status" {
				for _, val := range vals {
					lowerVal := strings.ToLower(val)
					if strings.Contains(lowerVal, "hit") || strings.Contains(lowerVal, "miss") {
						cacheFound = true
						mu.Lock()
						defer mu.Unlock()

						// Ensure the cache file is created and opened if not already done
						if cfg.Cachefile == nil {
							file, err := os.OpenFile("discoveredWebCache.txt", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)
							if err != nil {
								gologger.Fatal().Msgf("Error opening WebCache file: %v", err)
							}
							cfg.Cachefile = file
						}
						// Write the URL to the cache file
						_, err := fmt.Fprintf(cfg.Cachefile, "%s\n", fullURL)
						if err != nil {
							gologger.Fatal().Msgf("Error writing to WebCache file: %v\n", err)
						}
					}
				}
			}
		}
	}
	return cacheFound
}

// Save the URL To the success file
func saveSfile(url string) {
	if len(cfg.OutputFile) != 0 {
		if cfg.SuccessFile != nil {
			_, err := fmt.Fprintf(cfg.SuccessFile, "%s\n", url)
			if err != nil {
				gologger.Fatal().Msgf("Error writing To success file: %v\n", err)
			}
		}
	} else {
		return
	}
}

// filter responses and print the rest then store the outcofe to a file.
func filterPrintOut(result *Result, fSCodes, fCSize string) {
	fCSize_int64, _ := strconv.ParseInt(fCSize, 10, 64)
	statusConditions := (result.StatusCode >= 200 && result.StatusCode <= 299) ||
		result.StatusCode == 301 || result.StatusCode == 302 ||
		result.StatusCode == 307 || result.StatusCode == 401 ||
		result.StatusCode == 403 || result.StatusCode == 405 ||
		result.StatusCode == 500

	if statusConditions && len(cfg.FilterStatus) == 0 && len(cfg.FilterContentSize) != 0 && len(cfg.FilterStrings) != 0 {
		if !(strings.Contains(result.Status, fSCodes) && fSCodes == "all") || result.ContentSize == fCSize_int64 || result.Match {
			return
		} else {
			gologger.Print().Msgf("\r\033[K%s %s[ContentSize: %d, Status: %v]%s", result.URL, Cyan, result.ContentSize, result.Status, Reset)
			// Save the URL To the success file
			saveSfile(result.URL)
		}
	} else if statusConditions && len(cfg.FilterStatus) == 0 && len(cfg.FilterContentSize) == 0 && len(cfg.FilterStrings) != 0 {
		if !(strings.Contains(result.Status, fSCodes) && fSCodes == "all") && !(result.ContentSize == fCSize_int64) && result.Match {
			return
		} else {
			gologger.Print().Msgf("\r\033[K%s %s[ContentSize: %d, Status: %v]%s", result.URL, Cyan, result.ContentSize, result.Status, Reset)
			// Save the URL To the success file
			saveSfile(result.URL)
		}
	} else if statusConditions && len(cfg.FilterStatus) == 0 && len(cfg.FilterContentSize) != 0 && len(cfg.FilterStrings) == 0 {
		if !(strings.Contains(result.Status, fSCodes) && fSCodes == "all") && result.ContentSize == fCSize_int64 && !(result.Match) {
			return
		} else {
			gologger.Print().Msgf("\r\033[K%s %s[ContentSize: %d, Status: %v]%s", result.URL, Cyan, result.ContentSize, result.Status, Reset)
			// Save the URL To the success file
			saveSfile(result.URL)

		}
	} else if statusConditions && len(cfg.FilterStatus) != 0 && len(cfg.FilterContentSize) != 0 && len(cfg.FilterStrings) != 0 { // When all are Matcher and called
		if (strings.Contains(result.Status, fSCodes) || fSCodes == "all") || result.ContentSize == fCSize_int64 || result.Match {
			return
		} else {
			gologger.Print().Msgf("\r\033[K%s %s[ContentSize: %d, Status: %v]%s", result.URL, Cyan, result.ContentSize, result.Status, Reset)
			// Save the URL To the success file
			saveSfile(result.URL)

		}
	} else if statusConditions && len(cfg.FilterStatus) != 0 && len(cfg.FilterContentSize) != 0 && len(cfg.FilterStrings) == 0 { // When FilterStrings in not called
		if (strings.Contains(result.Status, fSCodes) || fSCodes == "all") || result.ContentSize == fCSize_int64 && !(result.Match) {
			return
		} else {
			gologger.Print().Msgf("\r\033[K%s %s[ContentSize: %d, Status: %v]%s", result.URL, Cyan, result.ContentSize, result.Status, Reset)
			// Save the URL To the success file
			saveSfile(result.URL)

		}
	} else if statusConditions && len(cfg.FilterStatus) != 0 && len(cfg.FilterContentSize) == 0 && len(cfg.FilterStrings) == 0 { // When just FilterStatus is called
		if (strings.Contains(result.Status, fSCodes) || fSCodes == "all") && !(result.ContentSize == fCSize_int64 && result.Match) {
			return
		} else {
			gologger.Print().Msgf("\r\033[K%s %s[ContentSize: %d, Status: %v]%s", result.URL, Cyan, result.ContentSize, result.Status, Reset)
			// Save the URL To the success file
			saveSfile(result.URL)

		}
	} else if statusConditions && len(cfg.FilterStatus) != 0 && len(cfg.FilterContentSize) == 0 && len(cfg.FilterStrings) != 0 { // When just FilterContentSize is not called
		if (strings.Contains(result.Status, fSCodes) || fSCodes == "all") && !(result.ContentSize == fCSize_int64) || result.Match {
			return
		} else {
			gologger.Print().Msgf("\r\033[K%s %s[ContentSize: %d, Status: %v]%s", result.URL, Cyan, result.ContentSize, result.Status, Reset)
			// Save the URL To the success file
			saveSfile(result.URL)
		}
	}
}

// Print out match responses, then store the outcome to a file.
func matchPrintOut(result *Result, mSCodes, mCSize string) {
	mCSize_int64, _ := strconv.ParseInt(mCSize, 10, 64)
	statusConditions := (result.StatusCode >= 200 && result.StatusCode <= 299) ||
		result.StatusCode == 301 || result.StatusCode == 302 ||
		result.StatusCode == 307 || result.StatusCode == 401 ||
		result.StatusCode == 403 || result.StatusCode == 405 ||
		result.StatusCode == 500

	if statusConditions && len(cfg.MatchStatus) == 0 && len(cfg.MatchContentSize) == 0 && len(cfg.MatchStrings) == 0 {
		gologger.Print().Msgf("\r\033[K%s %s[ContentSize: %d, Status: %v]%s", result.URL, Cyan, result.ContentSize, result.Status, Reset)
		// Save the URL To the success file
		saveSfile(result.URL)

		// When just MatchStatus is not called
	} else if len(cfg.MatchStatus) == 0 && len(cfg.MatchContentSize) != 0 && len(cfg.MatchStrings) != 0 {
		if mSCodes == "all" || result.ContentSize == mCSize_int64 || result.Match {
			gologger.Print().Msgf("\r\033[K%s %s[ContentSize: %d, Status: %v]%s", result.URL, Cyan, result.ContentSize, result.Status, Reset)
			// Save the URL To the success file
			saveSfile(result.URL)
		}

		// When just MatchStrings is called
	} else if len(cfg.MatchStatus) == 0 && len(cfg.MatchContentSize) == 0 && len(cfg.MatchStrings) != 0 {
		if mSCodes == "all" || !(result.ContentSize == mCSize_int64) && result.Match {
			gologger.Print().Msgf("\r\033[K%s %s[ContentSize: %d, Status: %v]%s", result.URL, Cyan, result.ContentSize, result.Status, Reset)
			// Save the URL To the success file
			saveSfile(result.URL)
		}

		// When just MatchContentSize is called
	} else if len(cfg.MatchStatus) == 0 && len(cfg.MatchContentSize) != 0 && len(cfg.MatchStrings) == 0 {
		if mSCodes == "all" || result.ContentSize == mCSize_int64 && !(result.Match) {
			gologger.Print().Msgf("\r\033[K%s %s[ContentSize: %d, Status: %v]%s", result.URL, Cyan, result.ContentSize, result.Status, Reset)
			// Save the URL To the success file
			saveSfile(result.URL)
		}

		// When all are Matcher and called
	} else if len(cfg.MatchStatus) != 0 && len(cfg.MatchContentSize) != 0 && len(cfg.MatchStrings) != 0 {
		if (strings.Contains(result.Status, mSCodes) || mSCodes == "all") || result.ContentSize == mCSize_int64 || result.Match {
			gologger.Print().Msgf("\r\033[K%s %s[ContentSize: %d, Status: %v]%s", result.URL, Cyan, result.ContentSize, result.Status, Reset)
			// Save the URL To the success file
			saveSfile(result.URL)
		}

		// When MatchStrings in not called
	} else if len(cfg.MatchStatus) != 0 && len(cfg.MatchContentSize) != 0 && len(cfg.MatchStrings) == 0 {
		if (strings.Contains(result.Status, mSCodes) || mSCodes == "all") || result.ContentSize == mCSize_int64 && !(result.Match) {
			gologger.Print().Msgf("\r\033[K%s %s[ContentSize: %d, Status: %v]%s", result.URL, Cyan, result.ContentSize, result.Status, Reset)
			// Save the URL To the success file
			saveSfile(result.URL)
		}

		// When just MatchStatus is called
	} else if len(cfg.MatchStatus) != 0 && len(cfg.MatchContentSize) == 0 && len(cfg.MatchStrings) == 0 {
		if (strings.Contains(result.Status, mSCodes) || mSCodes == "all") && !(result.ContentSize == mCSize_int64 && result.Match) {
			gologger.Print().Msgf("\r\033[K%s %s[ContentSize: %d, Status: %v]%s", result.URL, Cyan, result.ContentSize, result.Status, Reset)
			// Save the URL To the success file
			saveSfile(result.URL)
		}

		// When just MatchContentSize is not called
	} else if len(cfg.MatchStatus) != 0 && len(cfg.MatchContentSize) == 0 && len(cfg.MatchStrings) != 0 {
		if (strings.Contains(result.Status, mSCodes) || mSCodes == "all") || result.Match && !(result.ContentSize == mCSize_int64) {
			gologger.Print().Msgf("\r\033[K%s %s[ContentSize: %d, Status: %v]%s", result.URL, Cyan, result.ContentSize, result.Status, Reset)
			// Save the URL To the success file
			saveSfile(result.URL)
		}
	}
}

// Print out match and filter responses, then store the outcome to a file.
// func printOut(result *Result, mSCodes, mCSize, fSCodes, fCSize string, match, filter bool) {
// 	mCSize_int64, _ := strconv.ParseInt(mCSize, 10, 64)
// 	fCSize_int64, _ := strconv.ParseInt(fCSize, 10, 64)

// 	// statusConditions := (result.StatusCode >= 200 && result.StatusCode <= 299) ||
// 	// 	result.StatusCode == 301 || result.StatusCode == 302 ||
// 	// 	result.StatusCode == 307 || result.StatusCode == 401 ||
// 	// 	result.StatusCode == 403 || result.StatusCode == 405 ||
// 	// 	result.StatusCode == 500

// 	if match && filter {
// 		// panic(1)
// 		if (strings.Contains(result.Status, mSCodes) || mSCodes == "all") && !(result.ContentSize == mCSize_int64 && result.Match) {
// 			gologger.Print().Msgf("\r\033[K%s %s[ContentSize: %d, Status: %v]%s", result.URL, Cyan, result.ContentSize, result.Status, Reset)
// 			// Save the URL To the success file
// 			saveSfile(result.URL)
// 		}
// 	}
// }

// processResult handles the result of an HTTP request
func processResult(result *Result, cfg Config) {
	var mS string  // Match Status Code
	var mCS string // Match Content Size

	var fS string  // Filter Status Code
	var fCS string // Filter Content Size

	mSCode := cfg.MatchStatus      // slice Match Status Code
	mCSize := cfg.MatchContentSize // slice Match Content Size

	fSCode := cfg.FilterStatus      // slice Filter Status Code
	fCSize := cfg.FilterContentSize // slice Filter Content Size

	// allF := len(cfg.FilterStatus) != 0 && len(cfg.FilterStrings) != 0 && len(cfg.FilterContentSize) != 0
	zeroF := len(cfg.FilterStatus) == 0 && len(cfg.FilterStrings) == 0 && len(cfg.FilterContentSize) == 0
	// statusF := len(cfg.FilterStatus) != 0 && len(cfg.FilterStrings) == 0 && len(cfg.FilterContentSize) == 0
	// sizeF := len(cfg.FilterStatus) == 0 && len(cfg.FilterStrings) == 0 && len(cfg.FilterContentSize) != 0
	// stringF := len(cfg.FilterStatus) == 0 && len(cfg.FilterStrings) != 0 && len(cfg.FilterContentSize) == 0
	// status_stringF := len(cfg.FilterStatus) != 0 && len(cfg.FilterStrings) != 0 && len(cfg.FilterContentSize) == 0
	// status_sizeF := len(cfg.FilterStatus) != 0 && len(cfg.FilterStrings) == 0 && len(cfg.FilterContentSize) != 0
	// size_stringF := len(cfg.FilterStatus) == 0 && len(cfg.FilterStrings) != 0 && len(cfg.FilterContentSize) != 0

	// allM := len(cfg.MatchStatus) != 0 && len(cfg.MatchStrings) != 0 && len(cfg.MatchContentSize) != 0
	zeroM := len(cfg.MatchStatus) == 0 && len(cfg.MatchStrings) == 0 && len(cfg.MatchContentSize) == 0
	// statusM := len(cfg.MatchStatus) != 0 && len(cfg.MatchStrings) == 0 && len(cfg.MatchContentSize) == 0
	// sizeM := len(cfg.MatchStatus) == 0 && len(cfg.MatchStrings) == 0 && len(cfg.MatchContentSize) != 0
	// stringM := len(cfg.MatchStatus) == 0 && len(cfg.MatchStrings) != 0 && len(cfg.MatchContentSize) == 0
	// status_stringM := len(cfg.MatchStatus) != 0 && len(cfg.MatchStrings) != 0 && len(cfg.MatchContentSize) == 0
	// status_sizeM := len(cfg.MatchStatus) != 0 && len(cfg.MatchStrings) == 0 && len(cfg.MatchContentSize) != 0
	// size_stringM := len(cfg.MatchStatus) == 0 && len(cfg.MatchStrings) != 0 && len(cfg.MatchContentSize) != 0

	if len(cfg.MatchStatus) == 0 && len(cfg.MatchStrings) == 0 && len(cfg.MatchContentSize) == 0 && zeroF {
		matchPrintOut(result, mS, mCS)
	} else if len(cfg.MatchStrings) != 0 && len(cfg.MatchStatus) == 0 && len(cfg.MatchContentSize) == 0 && zeroF {
		matchPrintOut(result, mS, mCS)
	} else if len(cfg.MatchStatus) != 0 && len(cfg.MatchStrings) == 0 && len(cfg.MatchContentSize) == 0 && zeroF {
		for _, mSCodes := range mSCode {
			matchPrintOut(result, mSCodes, mCS)
		}
	} else if len(cfg.MatchStatus) != 0 && len(cfg.MatchStrings) != 0 && len(cfg.MatchContentSize) == 0 && zeroF {
		for _, mSCodes := range mSCode {
			matchPrintOut(result, mSCodes, mCS)
		}
	} else if len(cfg.MatchStatus) == 0 && len(cfg.MatchStrings) != 0 && len(cfg.MatchContentSize) != 0 && zeroF {
		for _, mCSizes := range mCSize {
			matchPrintOut(result, mS, mCSizes)
		}
	} else if len(cfg.MatchStatus) == 0 && len(cfg.MatchStrings) == 0 && len(cfg.MatchContentSize) != 0 && zeroF {
		for _, mCSizes := range mCSize {
			matchPrintOut(result, mS, mCSizes)
		}
	} else if len(cfg.MatchStatus) != 0 && len(cfg.MatchContentSize) != 0 && len(cfg.MatchStrings) == 0 && zeroF {
		for _, mSCodes := range mSCode {
			for _, mCSizes := range mCSize {
				matchPrintOut(result, mSCodes, mCSizes)
			}
		}
	} else if len(cfg.MatchStatus) != 0 && len(cfg.MatchContentSize) != 0 && len(cfg.MatchStrings) != 0 && zeroF {
		for _, mSCodes := range mSCode {
			for _, mCSizes := range mCSize {
				matchPrintOut(result, mSCodes, mCSizes)
			}
		}
	}

	if len(cfg.FilterStrings) != 0 && len(cfg.FilterStatus) == 0 && len(cfg.FilterContentSize) == 0 && zeroM {
		filterPrintOut(result, fS, fCS)
	} else if len(cfg.FilterStatus) != 0 && len(cfg.FilterStrings) == 0 && len(cfg.FilterContentSize) == 0 && zeroM {
		for _, fSCodes := range fSCode {
			filterPrintOut(result, fSCodes, fCS)
		}
	} else if len(cfg.FilterStatus) != 0 && len(cfg.FilterStrings) != 0 && len(cfg.FilterContentSize) == 0 && zeroM {
		for _, fSCodes := range fSCode {
			filterPrintOut(result, fSCodes, fCS)
		}
	} else if len(cfg.FilterStatus) == 0 && len(cfg.FilterStrings) != 0 && len(cfg.FilterContentSize) != 0 && zeroM {
		for _, fCSizes := range fCSize {
			filterPrintOut(result, fS, fCSizes)
		}
	} else if len(cfg.FilterStatus) == 0 && len(cfg.FilterStrings) == 0 && len(cfg.FilterContentSize) != 0 && zeroM {
		for _, fCSizes := range fCSize {
			filterPrintOut(result, fS, fCSizes)
		}
	} else if len(cfg.FilterStatus) != 0 && len(cfg.FilterContentSize) != 0 && len(cfg.FilterStrings) == 0 && zeroM {
		for _, fSCodes := range fSCode {
			for _, fCSizes := range fCSize {
				filterPrintOut(result, fSCodes, fCSizes)
			}
		}
	} else if len(cfg.FilterStatus) != 0 && len(cfg.FilterContentSize) != 0 && len(cfg.FilterStrings) != 0 && zeroM {
		for _, fSCodes := range fSCode {
			for _, fCSizes := range fCSize {
				filterPrintOut(result, fSCodes, fCSizes)
			}
		}
	}

	// if statusM && statusF {
	// 	for _, mSCodes := range mSCode {
	// 		for _, fSCodes := range fSCode {
	// 			printOut(result, mSCodes, mCS, fSCodes, fCS, statusM, statusF)
	// 		}
	// 	}
	// }
}

// rate limit for the http request
func rateLimit(fullURL string, sCode int, request *http.Request) {
	retryAttempts := 0
	maxRetries := cfg.Retries
	for retryAttempts < maxRetries {
		retryAttempts++
		// Exponential backoff: wait for 2^retryAttempts seconds before retrying
		backoffDuration := time.Duration(2<<retryAttempts+1) * time.Second
		// log.Printf(Yellow+"Received 429 Too Many Requests. Retrying in %v seconds..."+Reset, backoffDuration.Seconds())
		time.Sleep(backoffDuration)
		// cfg.httpClient To httpClient
		resp, err := httpClient.Do(request)
		if err != nil {
			debugModeEr(cfg.Debug, fullURL, err)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusTooManyRequests {
			break
		}
	}
	if sCode == http.StatusTooManyRequests {
		debugModeEr(cfg.Debug, fullURL, errors.New("429 TooManyRequests"))
		return
	}
}

// check if input(s) are number(s)
func checkNumber(numbers []interface{}) bool {
	for _, num := range numbers {
		// Type assertion to convert interface{} to string
		strNum, ok := num.(string)
		if !ok {
			// If the type assertion fails, it's not a string
			return false
		}

		_, err := strconv.Atoi(strNum)
		if err != nil {
			// If an error occurs during conversion, it's not a number
			return false
		}
	}

	// If all elements passed the checks, it contains only numbers
	return true
}

// to check if respdata contains a string
func matchRespData(body []byte, raw []string) bool {
	if len(raw) == 0 {
		return false
	}
	for _, data := range raw {
		if strings.Contains(strings.ToLower(string(body)), strings.ToLower(data)) {
			// fmt.Println(string(body))
			return true
		}
	}
	return false
}

// progbar initializes and returns a new progress bar with the specified number of steps
func progbar(progNum int) *progressbar.ProgressBar {
	if !cfg.Silent {
		gologger.Print().Msgf("%s %s", Banner, version)
		if cfg.HttpMethod == "" {
			gologger.Info().Msgf("HTTP Method : %s[GET]%s", Yellow, Reset)
		} else {
			gologger.Info().Msgf("HTTP Method : %s[%s]%s", Yellow, strings.ToUpper(cfg.HttpMethod), Reset)
		}
		gologger.Info().Msgf("Follow redirects : %s%v%s", Yellow, cfg.FollowRedirect, Reset)

		if len(cfg.MatchStatus) == 0 && len(cfg.MatchStrings) == 0 && len(cfg.MatchContentSize) == 0 || (len(cfg.FilterStrings) != 0 || len(cfg.FilterContentSize) != 0 || len(cfg.FilterStatus) != 0) {
			gologger.Info().Msgf("Match Status Code : %s[200-299,301,302,307,401,403,405,500]%s", Yellow, Reset)
		} else if len(cfg.MatchStatus) != 0 {
			gologger.Info().Msgf("Match Status Code : %s%v%s", Yellow, cfg.MatchStatus, Reset)
		}
		if len(cfg.MatchStrings) != 0 {
			gologger.Info().Msgf("Match Strings : %s%v%s", Yellow, cfg.MatchStrings, Reset)
		}
		if len(cfg.MatchContentSize) != 0 {
			gologger.Info().Msgf("Match ContentSize : %s%v%s", Yellow, cfg.MatchContentSize, Reset)
		}
		if len(cfg.FilterStatus) != 0 {
			gologger.Info().Msgf("Filter Status Code : %s%v%s", Yellow, cfg.FilterStatus, Reset)
		}
		if len(cfg.FilterStrings) != 0 {
			gologger.Info().Msgf("Filter Strings : %s%v%s", Yellow, cfg.FilterStrings, Reset)
		}
		if len(cfg.FilterContentSize) != 0 {
			gologger.Info().Msgf("Filter ContentSize : %s%v%s", Yellow, cfg.FilterContentSize, Reset)
		}
		if cfg.WebCache {
			gologger.Info().Msgf("Detect Web Cache : %sEnabled%s", Yellow, Reset)
		}
	}
	fmt.Println("----------------------------------------------------------------")
	fmt.Println("\r\033[K")
	bar := progressbar.NewOptions(progNum,
		progressbar.OptionSetWriter(os.Stderr),
		progressbar.OptionSetWidth(30),
		progressbar.OptionSetDescription("\r\033[KProcessing"),
		progressbar.OptionSetRenderBlankState(true),
		progressbar.OptionShowIts(),
		progressbar.OptionShowCount(),
		progressbar.OptionShowElapsedTimeOnFinish(),
		progressbar.OptionOnCompletion(func() {
			fmt.Fprint(os.Stderr, "\n")
		}),
		// progressbar.OptionSpinnerType(14),
		// progressbar.OptionThrottle(65*time.Millisecond),
	)

	return bar
}

// readInputFiles reads the wordlist and URLs from specified files
func readInputFiles(cfg Config) ([]string, []string) {
	var words, urls []string
	var err error

	if cfg.WordlistFile != "" {
		words, err = readLines(cfg.WordlistFile)
		if err != nil {
			gologger.Fatal().Msgf("Error reading wordlist: %v", err)
		}
	}

	if cfg.UrlFile != "" {
		urls, err = readLines(cfg.UrlFile)
		if err != nil {
			gologger.Fatal().Msgf("Error reading URLs: %v", err)
		}
	} else if len(cfg.UrlString) != 0 {
		urls = cfg.UrlString
	}

	return words, urls
}

// validateConfig performs initial validation on the configuration
func validateConfig() {
	// Validate status codes and sizes
	var statusList []interface{}
	for _, status := range cfg.MatchStatus {
		if status == "all" {
			break
		} else {
			statusList = append(statusList, status)
		}
	}
	for _, status := range cfg.FilterStatus {
		if status == "all" {
			break
		} else {
			statusList = append(statusList, status)
		}
	}
	if !checkNumber(statusList) {
		gologger.Fatal().Msgf("Invalid value: %v, For -fc/-mc", statusList)
	}

	var sizeList []interface{}
	for _, size := range cfg.MatchContentSize {
		sizeList = append(sizeList, size)
	}
	for _, size := range cfg.FilterContentSize {
		sizeList = append(sizeList, size)
	}
	if !checkNumber(sizeList) {
		gologger.Fatal().Msgf("Invalid value: %v, For -fl/-ml", sizeList)
	}

	// Check necessary configurations
	if !cfg.WebCache {
		if cfg.WordlistFile == "" && (cfg.UrlFile == "" && len(cfg.UrlString) == 0) {
			gologger.Fatal().Msgf(Red + "Please specify wordlist and target using -w/-wordlist, -l or -u" + Reset)
		} else if cfg.WordlistFile == "" {
			gologger.Fatal().Msgf(Red + "Please specify target using -w/-wordlist" + Reset)
		} else if cfg.UrlFile == "" && len(cfg.UrlString) == 0 {
			gologger.Fatal().Msgf(Red + "Please specify target using -l or -u" + Reset)
		}
	} else {
		if cfg.UrlFile == "" && len(cfg.UrlString) == 0 {
			gologger.Fatal().Msgf(Red + "Please specify target using -l or -u" + Reset)
		}
	}

	if !cfg.WebCache {
		if !strings.HasSuffix(cfg.WordlistFile, ".txt") || (!strings.HasSuffix(cfg.UrlFile, ".txt") && len(cfg.UrlString) == 0) {
			gologger.Fatal().Msgf(Red + "Wordlist and target files must have .txt extension." + Reset)
		}
	} else {
		if !strings.HasSuffix(cfg.UrlFile, ".txt") && len(cfg.UrlString) == 0 {
			gologger.Fatal().Msgf(Red + "Target file must have .txt extension." + Reset)
		}
	}
	if cfg.Concurrency == 0 {
		gologger.Fatal().Msgf("%s-c Can't Be 0%s", Red, Reset)
	}
	if (len(cfg.MatchStatus) != 0 || len(cfg.MatchStrings) != 0 || len(cfg.MatchContentSize) != 0) && (len(cfg.FilterStatus) != 0 || len(cfg.FilterStrings) != 0 || len(cfg.FilterContentSize) != 0) {
		gologger.Fatal().Msgf("%sCan't run any of the Match(s) and Filter(s) at the same time now%s", Red, Reset)
	}
}

// startRequests starts the HTTP requests using goroutines
func startRequests(ctx context.Context, wg *sync.WaitGroup, semaphore chan struct{}, bar *progressbar.ProgressBar, words, urls []string) {
	if cfg.WebCache && cfg.WordlistFile == "" {
		for _, url := range urls {
			wg.Add(1)               // Increment the wait group counter
			semaphore <- struct{}{} // acquire semaphore
			go webCacheRequest(url, wg, semaphore, ctx, cfg, bar)
		}
	} else {
		for _, word := range words {
			for _, url := range urls {
				wg.Add(1)               // Increment the wait group counter
				semaphore <- struct{}{} // acquire semaphore
				go makeRequest(url, word, wg, semaphore, ctx, cfg, bar)
			}
		}
	}
}

// The main func
func main() {
	// Check if no arguments are provided (excluding the program name)
	if len(os.Args) == 1 {
		fmt.Println("No arguments provided.[-h/--help for help]")
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
			gologger.Info().Msgf("[WARN] Caught keyboard: %v (Ctrl-C)", sig)
			fmt.Println("\r\033[K")
			cancel()
		case <-ctx.Done():
			// Context canceled, no need To handle signals
		}
	}()

	// Validate and process configurations
	validateConfig()

	if !cfg.FollowRedirect {
		httpClient.CheckRedirect = nil
	}

	// Read wordlist and URLs
	words, urls := readInputFiles(cfg)

	if cfg.OutputFile != "" {
		file, err := os.Create(cfg.OutputFile)
		if err != nil {
			gologger.Fatal().Msgf("Error creating success file: %v", err)
		}
		defer file.Close()
		cfg.SuccessFile = file
	}

	// Use a WaitGroup To wait for all goroutines To finish
	var wg sync.WaitGroup

	// Define a progress bar pointer
	var bar *progressbar.ProgressBar
	if cfg.WebCache && cfg.WordlistFile == "" {
		bar = progbar(len(urls))
	} else {
		bar = progbar(len(words) * len(urls))
	}

	// Create a semaphore To limit concurrency
	semaphore := make(chan struct{}, cfg.Concurrency)

	// Start the requests
	startRequests(ctx, &wg, semaphore, bar, words, urls)

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
