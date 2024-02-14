package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"

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
	"github.com/kataras/golog"
	"github.com/projectdiscovery/goflags"
	// "github.com/projectdiscovery/gologger"
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

var version = "v0.1.3"

const (
	Reset  = "\033[0m"
	Red    = "\033[31m"
	Blue   = "\033[34m"
	Yellow = "\033[33m"
	Cyan   = "\033[36m"
	Green  = "\033[32m"
	White  = "\033[37m"
	Banner = White + ` 
	 ██████╗ ███████╗██╗   ██╗███████╗███████╗
	██╔═══██╗██╔════╝██║   ██║╚══███╔╝╚══███╔╝
	██║   ██║█████╗  ██║   ██║  ███╔╝   ███╔╝ 
	██║▄▄ ██║██╔══╝  ██║   ██║ ███╔╝   ███╔╝  
	╚██████╔╝██║     ╚██████╔╝███████╗███████╗
	 ╚══▀▀═╝ ╚═╝      ╚═════╝ ╚══════╝╚══════╝
` + Reset
)

// Result struct To represent the result of an HTTP request
type Result struct {
	Status        int
	ContentLength int64
	URL           string
	Match         bool
}

type config struct {
	OutputFile      string
	WordlistFile    string
	UrlFile         string
	MatchStrings    goflags.StringSlice
	UserAgents      []string
	FollowRedirect  bool
	Verbose         bool
	RandomUserAgent bool
	Debug           bool
	Http2           bool
	WebCache        bool
	To              int
	Concurrency     int
	Retries         int
	SuccessFile     *os.File
	Cachefile       *os.File
	UrlString       goflags.StringSlice
	Headers         goflags.StringSlice
	PostData        string
	HttpMethod      string
}

var cfg config

func init() {
	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription("qfuzz, fuzz and more - " + version)
	flagSet.CreateGroup("input", "INPUT",
		flagSet.StringVarP(&cfg.WordlistFile, "w", "wordlist", "", "Wordlist file path"),
		flagSet.StringVarP(&cfg.UrlFile, "l", "list", "", "Target file path"),
		flagSet.StringSliceVar(&cfg.UrlString, "u", nil, "Target URL/URLs (-u https://example.com,https://example.org)", goflags.CommaSeparatedStringSliceOptions),
	)
	flagSet.CreateGroup("output", "OUTPUT",
		flagSet.StringVarP(&cfg.OutputFile, "o", "output", "", "Output file path"),
	)
	flagSet.CreateGroup("matchers", "MATCHERS",
		flagSet.StringSliceVarP(&cfg.MatchStrings, "ms", "match-strings", nil, "match response with specified string/strings (-mt example,Fuzz)", goflags.CommaSeparatedStringSliceOptions),
	)
	flagSet.CreateGroup("configurations", "CONFIGURATIONS",
		flagSet.StringVar(&cfg.HttpMethod, "X", "", "HTTP method To use in the request, (e.g., GET, POST, PUT, DELETE)"),
		flagSet.StringVarP(&cfg.PostData, "d", "data", "", "Data To include in the request body for POST method"),
		flagSet.StringSliceVar(&cfg.Headers, "H", nil, "Headers To include in the request, (e.g., 'key1:value1,key2:value2')", goflags.CommaSeparatedStringSliceOptions),
		flagSet.BoolVarP(&cfg.FollowRedirect, "fr", "follow-redirects", false, "Follow redirects"),
		flagSet.BoolVar(&cfg.WebCache, "webcache", false, "Detect web caching, (discoveredWebCache.txt)"),
		flagSet.BoolVar(&cfg.RandomUserAgent, "random-agent", true, "Enable Random User-Agent To use"),
		flagSet.IntVar(&cfg.Retries, "retries", 5, "number of Retries, if status code is 429"),
		flagSet.BoolVar(&cfg.Http2, "http2", false, "use HTTP2 protocol"),
	)
	flagSet.CreateGroup("optimizations", "OPTIMIZATIONS",
		flagSet.IntVar(&cfg.Concurrency, "c", 40, "number of concurrency To use"),
		flagSet.IntVarP(&cfg.To, "to", "timeout", 10, "timeout (seconds)"),
	)
	flagSet.CreateGroup("debug", "DEBUG",
		flagSet.BoolVarP(&cfg.Verbose, "verbose", "v", false, "Verbose mode"),
		flagSet.BoolVar(&cfg.Debug, "debug", false, "Debug mode (default true)"),
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
		// DisableKeepAlives:   false, // Enable connection reuse
		// DialContext: (&net.Dialer{
		// 	Timeout: time.Duration(time.Duration(cfg.To) * time.Second),
		// }).DialContext,
		// TLSHandshakeTimeout: time.Duration(time.Duration(cfg.To) * time.Second),
		// TLSClientConfig: &tls.Config{
		// InsecureSkipVerify: true,
		// 		MinVersion:         tls.VersionTLS10,
		// 		Renegotiation:      tls.RenegotiateOnceAsClient,
		// },
	},
}

func main() {
	startTime := time.Now()
	golog.SetTimeFormat("")
	golog.Print(Banner, version)
	// gologger.Print().Msgf("%s %s\n\n", Banner, version)

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
			golog.Info("Caught keyboard: ", sig, "(Ctrl-C)")
			// gologger.Info().Msgf("Caught keyboard: %v (Ctrl-C)", sig)
			cancel()
		case <-ctx.Done():
			// Context canceled, no need To handle signals
		}
	}()

	if cfg.HttpMethod == "" {
		golog.Info("HTTP Method : ", Yellow + "[GET]" + Reset)
		// gologger.Info().Msgf(Yellow + "HTTP Method [GET]" + Reset)
	} else {
		golog.Info("HTTP Method : ", Yellow, "[", strings.ToUpper(cfg.HttpMethod), "]", Reset)
		// gologger.Info().Msgf(Yellow+"HTTP Method [%s]"+Reset, strings.ToUpper(cfg.HttpMethod))
	}
	if !cfg.Verbose {
		golog.Info("Match Response Status : ", Yellow + "[200]" + Reset)
		// gologger.Info().Msgf(Yellow + "Match Response Status [200]" + Reset)
	} else {
		golog.Info("Match Response Status : ", Yellow + "[200-299,300-399,400-499,500-599]" + Reset)
		// gologger.Info().Msgf(Yellow + "Match Response Status [200-299,300-399,400-499,500-599]" + Reset)
	}
	if len(cfg.MatchStrings) > 0 {
		golog.Info("Match Title : ", Yellow, "Enable", cfg.MatchStrings, Reset)
		// gologger.Info().Msgf("Match Title : "+Yellow+"Enable %v"+Reset, cfg.MatchStrings)
	} // else {
	// 	golog.Info(Yellow + "Running In Defaul Mode" + Reset)
	// 	// gologger.Info().Msgf(Yellow + "Running In Defaul Mode" + Reset)
	// }
	if cfg.WebCache {
		golog.Info("Detect Web Cache : ", Yellow, "Enabled", Reset)
	}

	if cfg.WordlistFile == "" || (cfg.UrlFile == "" && len(cfg.UrlString) == 0) {
		golog.Fatal(Red + "Please specify wordlist and target using -w/-wordlist, -l or -u" + Reset)
		// gologger.Fatal().Msgf(Red + "Please specify wordlist and target using -w/-wordlist, -l or -u" + Reset)
	}

	if !strings.HasSuffix(cfg.WordlistFile, ".txt") || (!strings.HasSuffix(cfg.UrlFile, ".txt") && len(cfg.UrlString) == 0) {
		golog.Fatal(Red + "Wordlist and target files must have .txt extension." + Reset)
		// gologger.Fatal().Msgf(Red + "Wordlist and target files must have .txt extension." + Reset)
	}

	if !cfg.FollowRedirect {
		httpClient.CheckRedirect = nil
	}

	if cfg.Concurrency == 0 {
		golog.Fatal(Red, "-c Can't Be 0", Reset)
		// gologger.Fatal().Msgf("%s-c Can't Be 0%s", Red, Reset)
	}

	// Read words from a wordlist file
	words, err := readLines(cfg.WordlistFile)
	if err != nil {
		golog.Fatal("Error reading wordlist:", err)
		// gologger.Fatal().Msgf("Error reading wordlist:", err)
		return
	}

	var urls []string
	if cfg.UrlFile != "" {
		urls, err = readLines(cfg.UrlFile)
		if err != nil {
			golog.Fatal("Error reading URLs: ", err)
			// gologger.Fatal().Msgf("Error reading URLs:", err)
			return
		}
	} else if len(cfg.UrlString) > 0 {
		urls = cfg.UrlString
	}

	if cfg.OutputFile != "" {
		cfg.SuccessFile, err = os.Create(cfg.OutputFile)
		if err != nil {
			golog.Fatal("Error creating success file: ", err)
			// gologger.Fatal().Msgf("Error creating success file: %v\n", err)
		}
		defer cfg.SuccessFile.Close()
	}

	if cfg.WebCache {
		cfg.Cachefile, err = os.OpenFile("discoveredWebCache.txt", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)
		if err != nil {
			golog.Fatal("Error opening log file: ", err)
			// gologger.Fatal().Msgf("Error opening log file: %s", err)
		}
		defer cfg.Cachefile.Close()
	}

	// Use a WaitGroup To wait for all goroutines To finish
	var wg sync.WaitGroup

	// Create a semaphore To limit concurrency
	semaphore := make(chan struct{}, cfg.Concurrency)

	for _, word := range words {
		for _, url := range urls {
			wg.Add(1)               // Increment the wait group counter
			semaphore <- struct{}{} // acquire semaphore
			go makeRequest(url, word, &wg, semaphore, ctx, cfg)
		}
	}

	// Start a goroutine To close the results channel once all requests are done
	go func() {
		wg.Wait()
		close(semaphore)
	}()

	// Optionally wait for a user interrupt To exit gracefully
	select {
	case <-ctx.Done():
		// Context canceled, exit gracefully
		return
	default:
	}

	elapsedTime := time.Since(startTime)
	golog.Info("Total time taken: ", elapsedTime)
	// gologger.Info().Msgf("Total time taken: %s\n", elapsedTime)
}

func makeRequest(url, word string, wg *sync.WaitGroup, semaphore chan struct{}, ctx context.Context, cfg config) {
	defer func() {
		<-semaphore // release semaphore
		wg.Done()
	}()

	var fullURL string

	urls, err := neturl.Parse(url)
	if err != nil {
		golog.Error(Red, "Invalid URL: ", url, Reset)
		// gologger.Error().Msgf(Red + "Invalid URL: " + url + Reset)
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

	if len(cfg.Headers) > 0 {
		for _, pair := range cfg.Headers {
			result := strings.Split(pair, ":")
			key, value := result[0], result[1]
			request.Header.Set(key, value)
		}
		// Check if "User-Agent" header is present, and if not, add it
		if _, exists := request.Header["User-Agent"]; !exists {
			request.Header.Set("User-Agent", getRandomUserAgent())
		}
	} else if len(cfg.Headers) == 0 && cfg.RandomUserAgent {
		request.Header.Set("User-Agent", getRandomUserAgent())
	}

	// If it's a POST request and data is provided, include data in the request body
	if request.Method == "POST" && cfg.PostData != "" {
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

	if cfg.WebCache {
		// gologger.Info().Msg("Web Cache")
		for key := range resp.Header {
			if detectWebCache(key, fullURL) {
				break
			}
		}
	}

	if resp.StatusCode == http.StatusTooManyRequests {
		rateLimit(fullURL, resp.StatusCode, request)
	}

	var result Result
	result.Status = resp.StatusCode
	result.ContentLength = resp.ContentLength
	result.URL = fullURL

	if len(cfg.MatchStrings) > 0 && resp.StatusCode == http.StatusOK {
		result.Match = detectBodyMatch(fullURL, resp)
	}

	// Process the result
	processResult(result, cfg)
}

func detectWebCache(key, fullURL string) bool {
	var cacheHeaders = []string{"X-Cache", "Cache-Control", "Vary", "Age", "Server-Timing"}
	for _, header := range cacheHeaders {
		if strings.EqualFold(key, header) {
			// Save the URL To the success file
			_, err := fmt.Fprintf(cfg.Cachefile, "%s\n", fullURL)
			if err != nil {
				golog.Fatal("Error writing To WebCache file: ", err)
				// gologger.Fatal().Msgf("Error writing To success file: %v\n", err)
			}
			return true
		}
	}
	return false
}

// processResult handles the result of an HTTP request
func processResult(result Result, cfg config) {
	if result.Status == http.StatusOK && cfg.SuccessFile != nil {
		// Save the URL To the success file
		_, err := fmt.Fprintf(cfg.SuccessFile, "%s\n", result.URL)
		if err != nil {
			golog.Fatal("Error writing To success file: ", err)
			// gologger.Fatal().Msgf("Error writing To success file: %v\n", err)
		}
		golog.Info("[", Cyan, result.Status, Reset, "]", " ", result.URL, " ", "[", result.ContentLength, "]", " ", (Green + "[Found]" + Reset))
		// gologger.Info().Msgf("[%s%d%s] %s [%d] %s", Cyan, result.Status, Reset, result.URL, result.ContentLength, (Green + "[Found]" + Reset))
	} else if result.Status != http.StatusOK && cfg.SuccessFile != nil && !result.Match && cfg.Verbose {
		verboseMode(cfg.Verbose, result.Status, result.URL, result.ContentLength)
	} else if len(cfg.MatchStrings) > 0 {
		if result.Match {
			if cfg.SuccessFile != nil {
				// Save the URL To the success file
				_, err := fmt.Fprintf(cfg.SuccessFile, "%s\n", result.URL)
				if err != nil {
					golog.Fatal("Error writing To success file: ", err)
					// gologger.Fatal().Msgf("Error writing To success file: %v\n", err)
				}
				golog.Info("[", Cyan, result.Status, Reset, "]", " ", result.URL, " ", "[", result.ContentLength, "]", " ", (Green + "[Found]" + Reset))
				// gologger.Info().Msgf("[%s%d%s] %s [%d] %s", Cyan, result.Status, Reset, result.URL, result.ContentLength, (Green + "[Found]" + Reset))
			} else {
				golog.Info("[", Cyan, result.Status, Reset, "]", " ", result.URL, " ", "[", result.ContentLength, "]", " ", (Green + "[Found]" + Reset))
				// gologger.Info().Msgf("[%s%d%s] %s [%d] %s", Cyan, result.Status, Reset, result.URL, result.ContentLength, (Green + "[Found]" + Reset))
			}
		} else {
			if cfg.SuccessFile != nil {
				verboseMode(cfg.Verbose, result.Status, result.URL, result.ContentLength)
			} else {
				verboseMode(cfg.Verbose, result.Status, result.URL, result.ContentLength)
			}
		}
	} else if result.Status == http.StatusOK && len(cfg.MatchStrings) == 0 && cfg.SuccessFile == nil {
		golog.Info("[", Cyan, result.Status, Reset, "]", " ", result.URL, " ", "[", result.ContentLength, "]", " ", (Green + "[Found]" + Reset))
		// gologger.Info().Msgf("[%s%d%s] %s [%d] %s", Cyan, result.Status, Reset, result.URL, result.ContentLength, (Green + "[Found]" + Reset))
	} else if result.Status != http.StatusOK && len(cfg.MatchStrings) == 0 && cfg.SuccessFile == nil && cfg.Verbose {
		verboseMode(cfg.Verbose, result.Status, result.URL, result.ContentLength)
	}
}

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

func readResponseBody(resp *http.Response) ([]byte, error) {
	// Create a new io.Reader from the response body
	bodyReader := resp.Body

	// Read the response body into a buffer
	var bodyBuffer bytes.Buffer
	_, err := io.Copy(&bodyBuffer, bodyReader)

	// Close the response body
	bodyReader.Close()

	if err != nil {
		golog.Error((Yellow + "Error reading response body: " + Reset), err)
		// gologger.Error().Msgf(Yellow+"Error reading response body: %v"+Reset, err)
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
		debugModeEr(cfg.Debug, fullURL, err)
		return false
	}

	bodyReader := bytes.NewReader(body)
	bodyTitle, err := goquery.NewDocumentFromReader(bodyReader)
	if err != nil {
		debugModeEr(cfg.Debug, fullURL, err)
		return false
	}

	title := bodyTitle.Find("title").Text()
	responseText := bodyTitle.Text()

	if matchRespString([]byte(responseText), cfg.MatchStrings) || matchRespString([]byte(title), cfg.MatchStrings) {
		return true
	} else {
		return false
	}
}

func verboseMode(Verbose bool, sCode int, fUrl string, cLen int64) {
	if Verbose {
		if sCode == 404 {
			// gologger.Error().Msgf("[%s%d%s] %s [%d] %s", Red, sCode, Reset, fUrl, cLen, (Red + "[Not Found]" + Reset))
			golog.Error("[", Red, sCode, Reset, "]", " ", fUrl, " ", "[", cLen, "]", " ", (Red + "[Not Found]" + Reset))
		} else if sCode == 401 {
			golog.Error("[", Red, sCode, Reset, "]", " ", fUrl, " ", "[", cLen, "]", " ", (Red + "[Unauthorized]" + Reset))
			// gologger.Error().Msgf("[%s%d%s] %s [%d] %s", Red, sCode, Reset, fUrl, cLen, (Red + "[Unauthorized]" + Reset))
		} else if sCode == 400 {
			golog.Error("[", Red, sCode, Reset, "]", " ", fUrl, " ", "[", cLen, "]", " ", (Red + "[Bad Request]" + Reset))
			// gologger.Error().Msgf("[%s%d%s] %s [%d] %s", Red, sCode, Reset, fUrl, cLen, (Red + "[Bad Request]" + Reset))
		} else if sCode == 403 {
			golog.Error("[", Red, sCode, Reset, "]", " ", fUrl, " ", "[", cLen, "]", " ", (Red + "[Forbidden]" + Reset))
			// gologger.Error().Msgf("[%s%d%s] %s [%d] %s", Red, sCode, Reset, fUrl, cLen, (Red + "[Forbidden]" + Reset))
		} else if sCode == 405 {
			golog.Error("[", Red, sCode, Reset, "]", " ", fUrl, " ", "[", cLen, "]", " ", (Red + "[Method Not Allowed]" + Reset))
			// gologger.Warning().Msgf("[%s%d%s] %s [%d] %s", Red, sCode, Reset, fUrl, cLen, (Red + "[Method Not Allowed]" + Reset))
		} else if sCode == 429 {
			golog.Warn("[", Red, sCode, Reset, "]", " ", fUrl, " ", "[", cLen, "]", " ", (Red + "[Rate Limited]" + Reset))
			// gologger.Warning().Msgf("[%s%d%s] %s [%d] %s", Red, sCode, Reset, fUrl, cLen, (Red + "[Rate Limited]" + Reset))
		} else if sCode == 301 {
			golog.Warn("[", Yellow, sCode, Reset, "]", " ", fUrl, " ", "[", cLen, "]", " ", (Yellow + "[Moved Permanently]" + Reset))
			// gologger.Warning().Msgf("[%s%d%s] %s [%d] %s", Yellow, sCode, Reset, fUrl, cLen, (Yellow + "[Moved Permanently]" + Reset))
		} else if sCode == 302 {
			golog.Warn("[", Yellow, sCode, Reset, "]", " ", fUrl, " ", "[", cLen, "]", " ", (Yellow + "[Redirect Found]" + Reset))
			// gologger.Warning().Msgf("[%s%d%s] %s [%d] %s", Yellow, sCode, Reset, fUrl, cLen, (Yellow + "[Redirect Found]" + Reset))
		} else if sCode == 307 {
			golog.Warn("[", Yellow, sCode, Reset, "]", " ", fUrl, " ", "[", cLen, "]", " ", (Yellow + "[Temporary Redirect]" + Reset))
			// gologger.Warning().Msgf("[%s%d%s] %s [%d] %s", Yellow, sCode, Reset, fUrl, cLen, (Yellow + "[Temporary Redirect]" + Reset))
		} else if sCode == 500 {
			golog.Warn("[", Red, sCode, Reset, "]", " ", fUrl, " ", "[", cLen, "]", " ", (Red + "[Internal Server Error]" + Reset))
			// gologger.Warning().Msgf("[%s%d%s] %s [%d] %s", Red, sCode, Reset, fUrl, cLen, (Red + "[Internal Server Error]" + Reset))
		} else if sCode == 503 {
			golog.Warn("[", Red, sCode, Reset, "]", " ", fUrl, " ", "[", cLen, "]", " ", (Red + "[Service Unavailable]" + Reset))
			// gologger.Warning().Msgf("[%s%d%s] %s [%d] %s", Red, sCode, Reset, fUrl, cLen, (Red + "[Service Unavailable]" + Reset))
		} else {
			golog.Warn("[", Red, sCode, Reset, "]", " ", fUrl, " ", "[", cLen, "]")
			// gologger.Info().Msgf("[%s%d%s] %s [%d]", Red, sCode, Reset, fUrl, cLen)
		}
	}
}

func debugModeEr(debug bool, urlStr string, message error) {
	if debug {
		golog.Error("Error making GET request To ", urlStr, " : ", message)
		// gologger.Error().Msgf("Error making GET request To %s: %v", urlStr, message)
	}
}

// Select a random User-Agent from the list
func getRandomUserAgent() string {
	return cfg.UserAgents[rand.Intn(len(cfg.UserAgents))]
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
