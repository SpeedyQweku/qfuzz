package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"

	"context"
	"math/rand"
	"net/http"
	neturl "net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
	// "net"
	// "crypto/tls"

	"github.com/PuerkitoBio/goquery"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
)

var (
	requestPool = sync.Pool{
		New: func() interface{} {
			return new(http.Request)
		},
	}
	responsePool = sync.Pool{
		New: func() interface{} {
			return new(http.Response)
		},
	}
)

const (
	Reset  = "\033[0m"
	Red    = "\033[31m"
	Blue   = "\033[34m"
	Yellow = "\033[33m"
	Cyan   = "\033[36m"
	Green  = "\033[32m"
)

// Result struct to represent the result of an HTTP request
type Result struct {
	Status   int
	ContentLength int64
	URL      string
	Match    bool
}

type config struct {
	outputFile      string
	wordlistFile    string
	urlFile         string
	matchStrings    goflags.StringSlice
	userAgents      []string
	followRedirect  bool
	verbose         bool
	randomUserAgent bool
	silent          bool
	to              int
	cConcurrency    int
	retries         int
	Http2           bool
	successFile     *os.File
}

var cfg config

func init() {
	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription("dfuzz, fuzz urls for secrets...")
	flagSet.CreateGroup("input", "INPUT",
		flagSet.StringVarP(&cfg.wordlistFile, "wordlist", "w", "", "Wordlist file path"),
		flagSet.StringVarP(&cfg.urlFile, "l", "list", "", "Target file path"),
	)
	flagSet.CreateGroup("output", "OUTPUT",
		flagSet.StringVarP(&cfg.outputFile, "output", "o", "", "Output file path"),
	)
	flagSet.CreateGroup("matchers", "MATCHERS",
		flagSet.StringSliceVarP(&cfg.matchStrings, "match-strings", "ms", nil, "match response with specified string/strings (-mt example,Fuzz)", goflags.CommaSeparatedStringSliceOptions),
	)
	flagSet.CreateGroup("optimizations", "OPTIMIZATIONS",
		flagSet.IntVar(&cfg.cConcurrency, "c", 40, "number of concurrency to use"),
		flagSet.IntVarP(&cfg.to, "to", "timeout", 10, "timeout (seconds)"),
	)
	flagSet.CreateGroup("configurations", "CONFIGURATIONS",
		flagSet.BoolVarP(&cfg.followRedirect, "fr", "follow-redirects", false, "Follow redirects"),
		flagSet.BoolVar(&cfg.randomUserAgent, "random-agent", true, "enable Random User-Agent to use"),
		flagSet.IntVar(&cfg.retries, "retries", 5, "number of retries, if status code is 429"),
		flagSet.BoolVar(&cfg.Http2, "http2", false, "use HTTP2 protocol"),
	)
	flagSet.CreateGroup("debug", "DEBUG",
		flagSet.BoolVarP(&cfg.verbose, "verbose", "v", false, "verbose mode"),
		flagSet.BoolVarP(&cfg.silent, "silent", "s", false, "silent mode (default true)"),
	)

	_ = flagSet.Parse()

	// User-Agent list
	cfg.userAgents = []string{
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
	Timeout:       time.Duration(time.Duration(cfg.to) * time.Second),
	Transport: &http.Transport{
		ForceAttemptHTTP2:   cfg.Http2,
		MaxIdleConns:        1000,
		MaxIdleConnsPerHost: 500,
		MaxConnsPerHost:     500,
		IdleConnTimeout:     time.Duration(time.Duration(cfg.to) * time.Second),
		// DisableKeepAlives:   false, // Enable connection reuse
		// DialContext: (&net.Dialer{
		// 	Timeout: time.Duration(time.Duration(cfg.to) * time.Second),
		// }).DialContext,
		// TLSHandshakeTimeout: time.Duration(time.Duration(cfg.to) * time.Second),
		// TLSClientConfig: &tls.Config{
		// InsecureSkipVerify: true,
		// 		MinVersion:         tls.VersionTLS10,
		// 		Renegotiation:      tls.RenegotiateOnceAsClient,
		// },
	},
}

func main() {
	startTime := time.Now()
	gologger.Info().Msg("dfuzz is running...")

	// Create a context with cancellation ability
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // Ensure the context is canceled when main function exits

	// Set up signal handling
	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, os.Interrupt, syscall.SIGTERM)

	// Start a goroutine to listen for signals and cancel the context on signal
	go func() {
		select {
		case sig := <-signalCh:
			gologger.Info().Msgf("Caught keyboard: %v (Ctrl-C)", sig)
			cancel()
		case <-ctx.Done():
			// Context canceled, no need to handle signals
		}
	}()

	if len(cfg.matchStrings) > 0 {
		gologger.Info().Msgf("Match Title : "+Yellow+"Enable %v"+Reset, cfg.matchStrings)
	} else {
		gologger.Info().Msgf(Yellow + "Running In Defaul Mode" + Reset)
	}

	if cfg.wordlistFile == "" || cfg.urlFile == "" {
		gologger.Fatal().Msgf(Red + "Please specify wordlist and target using -w/-wordlist and -l" + Reset)
	}

	if !strings.HasSuffix(cfg.wordlistFile, ".txt") || !strings.HasSuffix(cfg.urlFile, ".txt") {
		gologger.Fatal().Msgf(Red + "Wordlist and target files must have .txt extension." + Reset)
	}

	if !cfg.followRedirect {
		httpClient.CheckRedirect = nil
	}

	if cfg.cConcurrency == 0 {
		gologger.Fatal().Msgf("%s-c Can't Be 0%s", Red, Reset)
	}

	// Read words from a wordlist file
	words, err := readLines(cfg.wordlistFile)
	if err != nil {
		gologger.Fatal().Msgf("Error reading wordlist:", err)
		return
	}

	urls, err := readLines(cfg.urlFile)
	if err != nil {
		gologger.Fatal().Msgf("Error reading URLs:", err)
		return
	}

	if cfg.outputFile != "" {
		cfg.successFile, err = os.Create(cfg.outputFile)
		if err != nil {
			gologger.Fatal().Msgf("Error creating success file: %v\n", err)
		}
		defer cfg.successFile.Close()
	}

	// Use a WaitGroup to wait for all goroutines to finish
	var wg sync.WaitGroup

	// Create a semaphore to limit concurrency
	semaphore := make(chan struct{}, cfg.cConcurrency)

	for _, word := range words {
		for _, url := range urls {
			wg.Add(1)               // Increment the wait group counter
			semaphore <- struct{}{} // acquire semaphore
			go makeRequest(url, word, &wg, semaphore, ctx, cfg.successFile)
		}
	}

	// Start a goroutine to close the results channel once all requests are done
	go func() {
		wg.Wait()
		close(semaphore)
	}()

	// Optionally wait for a user interrupt to exit gracefully
	select {
	case <-ctx.Done():
		// Context canceled, exit gracefully
		return
	default:
	}

	elapsedTime := time.Since(startTime)
	gologger.Info().Msgf("Total time taken: %s\n", elapsedTime)
}

func makeRequest(url, word string, wg *sync.WaitGroup, semaphore chan struct{}, ctx context.Context, successFile *os.File) {
	defer func() {
		<-semaphore // release semaphore
		wg.Done()
	}()

	var fullURL string

	urls, err := neturl.Parse(url)
	if err != nil {
		gologger.Error().Msgf(Red + "Invalid URL: " + url + Reset)
		return
	}
	if urls.Scheme == "" {
		urls.Scheme = "https"
	}

	if strings.HasPrefix(word, "/") {
		word = strings.TrimLeft(word, "/")
	}
	if strings.HasSuffix(urls.String(), "/") {
		urlstr := strings.TrimRight(urls.String(), "/")
		fullURL = fmt.Sprintf("%s/%s", urlstr, word)
	} else {
		fullURL = fmt.Sprintf("%s/%s", urls.String(), word)
	}

	// Reuse http.Request and http.Response using sync.Pool
	request := acquireRequest()
	defer releaseRequest(request)
	request.URL, _ = neturl.Parse(fullURL)

	// Set User-Agent in the request header
	if request.Header == nil {
		request.Header = make(http.Header)
	}

	if cfg.randomUserAgent {
		request.Header.Set("User-Agent", getRandomUserAgent())
	} else {
		request.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
	}

	response := acquireResponse()
	defer releaseResponse(response)
	// Optionally wait for a user interrupt to exit gracefully
	select {
	case <-ctx.Done():
		// Context canceled, exit gracefully
		return
	default:
	}

	// Make the HTTP request
	resp, err := httpClient.Do(request.WithContext(ctx))
	if err != nil {
		silentModeEr(cfg.silent, fullURL, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		rateLimit(fullURL, resp.StatusCode, request)
	}

	var result Result
	result.Status = resp.StatusCode
	result.ContentLength = resp.ContentLength
	result.URL = fullURL

	if len(cfg.matchStrings) > 0 && resp.StatusCode == http.StatusOK {
		result.Match = detectBodyMatch(fullURL, resp)
	}

	// Process the result
	processResult(result, successFile, cfg.verbose, cfg.silent)
}

// processResult handles the result of an HTTP request
func processResult(result Result, successFile *os.File, verbose, silent bool) {
	if result.Status == http.StatusOK && successFile != nil && result.Match {
		// Save the URL to the success file
		_, err := fmt.Fprintf(successFile, "%s\n", result.URL)
		if err != nil {
			gologger.Fatal().Msgf("Error writing to success file: %v\n", err)
		}
		gologger.Info().Msgf("[%s%d%s] %s [%d] %s", Cyan, result.Status, Reset, result.URL, result.ContentLength, (Green + "[Found]" + Reset))
	} else if result.Status != http.StatusOK && successFile != nil && !result.Match && verbose {
		verboseMode(verbose, result.Status, result.URL, result.ContentLength)
	} else if len(cfg.matchStrings) > 0 {
		if result.Match {
			if successFile != nil {
				// Save the URL to the success file
				_, err := fmt.Fprintf(successFile, "%s\n", result.URL)
				if err != nil {
					gologger.Fatal().Msgf("Error writing to success file: %v\n", err)
				}
				gologger.Info().Msgf("[%s%d%s] %s [%d] %s", Cyan, result.Status, Reset, result.URL, result.ContentLength, (Green + "[Found]" + Reset))
			} else {
				gologger.Info().Msgf("[%s%d%s] %s [%d] %s", Cyan, result.Status, Reset, result.URL, result.ContentLength, (Green + "[Found]" + Reset))
			}
		} else {
			if successFile != nil {
				verboseMode(verbose, result.Status, result.URL, result.ContentLength)
			} else {
				verboseMode(verbose, result.Status, result.URL, result.ContentLength)
			}
		}
	} else if result.Status == http.StatusOK && len(cfg.matchStrings) == 0 && successFile == nil {
		gologger.Info().Msgf("[%s%d%s] %s [%d] %s", Cyan, result.Status, Reset, result.URL, result.ContentLength, (Green + "[Found]" + Reset))
	} else if result.Status != http.StatusOK && len(cfg.matchStrings) == 0 && successFile == nil && verbose {
		verboseMode(verbose, result.Status, result.URL, result.ContentLength)
	}
}

func rateLimit(fullURL string, sCode int, request *http.Request) {
	retryAttempts := 0
	maxRetries := cfg.retries
	for retryAttempts < maxRetries {
		retryAttempts++
		// Exponential backoff: wait for 2^retryAttempts seconds before retrying
		backoffDuration := time.Duration(2<<retryAttempts+1) * time.Second
		// log.Printf(Yellow+"Received 429 Too Many Requests. Retrying in %v seconds..."+Reset, backoffDuration.Seconds())
		time.Sleep(backoffDuration)
		// cfg.httpClient To httpClient
		resp, err := httpClient.Do(request)
		if err != nil {
			silentModeEr(cfg.silent, fullURL, err)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusTooManyRequests {
			break
		}
	}
	if sCode == http.StatusTooManyRequests {
		silentModeEr(cfg.silent, fullURL, errors.New("429 TooManyRequests"))
		return
	}
}

func readResponseBody(resp *http.Response) ([]byte, error) {
	// Create a new io.Reader from the response body
	bodyReader := resp.Body

	// Read the response body into a buffer
	var bodyBuffer bytes.Buffer
	_, err := io.Copy(&bodyBuffer, bodyReader)

	// Close the response body
	bodyReader.Close()

	if err != nil {
		gologger.Error().Msgf(Yellow+"Error reading response body: %v"+Reset, err)
		return nil, err
	}

	return bodyBuffer.Bytes(), nil
}

func matchRespString(body []byte, titles []string) bool {
	if len(titles) == 0 {
		return false
	}
	for _, title := range titles {
		if strings.Contains(strings.ToLower(string(body)), strings.ToLower(title)) {
			return true
		}
	}
	return false
}

func detectBodyMatch(fullURL string, resp *http.Response) bool {
	body, err := readResponseBody(resp)
	if err != nil {
		silentModeEr(cfg.silent, fullURL, err)
		return false
	}

	bodyReader := bytes.NewReader(body)
	bodyTitle, err := goquery.NewDocumentFromReader(bodyReader)
	if err != nil {
		silentModeEr(cfg.silent, fullURL, err)
		return false
	}

	title := bodyTitle.Find("title").Text()
	responseText := bodyTitle.Text()

	if matchRespString([]byte(responseText), cfg.matchStrings) || matchRespString([]byte(title), cfg.matchStrings) {
		return true
	} else {
		return false
	}
}

func verboseMode(verbose bool, sCode int, fUrl string, cLen int64) {
	if verbose {
		if sCode == 404 {
			gologger.Error().Msgf("[%s%d%s] %s [%d] %s", Red, sCode, Reset, fUrl, cLen, (Red + "[Not Found]" + Reset))
		} else if sCode == 403 {
			gologger.Error().Msgf("[%s%d%s] %s [%d] %s", Yellow, sCode, Reset, fUrl, cLen, (Yellow + "[Forbidden]" + Reset))
		} else if sCode == 429 {
			gologger.Warning().Msgf("[%s%d%s] %s [%d] %s", Yellow, sCode, Reset, fUrl, cLen, (Yellow + "[Rate Limited]" + Reset))
		} else {
			gologger.Info().Msgf("[%s%d%s] %s [%d]", Red, sCode, Reset, fUrl, cLen)
		}
	}
}

func silentModeEr(silent bool, urlStr string, message error) {
	if silent {
		gologger.Error().Msgf("Error making GET request to %s: %v", urlStr, message)
	}
}

// Select a random User-Agent from the list
func getRandomUserAgent() string {
	return cfg.userAgents[rand.Intn(len(cfg.userAgents))]
}

// HTTP Pool
func acquireRequest() *http.Request {
	return requestPool.Get().(*http.Request)
}
func releaseRequest(req *http.Request) {
	req.URL = nil
	requestPool.Put(req)
}
func acquireResponse() *http.Response {
	return responsePool.Get().(*http.Response)
}
func releaseResponse(resp *http.Response) {
	responsePool.Put(resp)
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
