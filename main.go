package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net/http"
	neturl "net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
)

const (
	Reset  = "\033[0m"
	Red    = "\033[31m"
	Blue   = "\033[34m"
	Yellow = "\033[33m"
	Cyan   = "\033[36m"
)

type job struct {
	url  string
	word string
}

// // Newly add
// type batch struct {
//     urls []string
//     word string
// }
// // end of it

type result struct {
	url        string
	status     int
	contentLen int64
	body       *http.Response
}

var (
	httpClient      *http.Client
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
	cConcurrency     int
	retries         int
)

func init() {
	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription("dfuzz, fuzz urls for secrets...")
	flagSet.CreateGroup("input", "INPUT",
		flagSet.StringVarP(&wordlistFile, "wordlist", "w", "", "Wordlist file path"),
		flagSet.StringVarP(&urlFile, "l", "list", "", "Target file path"),
	)
	flagSet.CreateGroup("output", "OUTPUT",
		flagSet.StringVarP(&outputFile, "output", "o", "", "Output file path"),
	)
	flagSet.CreateGroup("matchers", "MATCHERS",
		flagSet.StringSliceVarP(&matchStrings, "match-strings", "ms", nil, "match response with specified string/strings (-mt example,Fuzz)", goflags.CommaSeparatedStringSliceOptions),
	)
	flagSet.CreateGroup("optimizations", "OPTIMIZATIONS",
		flagSet.IntVar(&cConcurrency, "c", 50, "number of concurrency to use"),
		flagSet.IntVarP(&to, "to", "timeout", 10, "timeout (seconds)"),
	)
	flagSet.CreateGroup("configurations", "CONFIGURATIONS",
		flagSet.BoolVarP(&followRedirect, "fr", "follow-redirects", false, "Follow redirects"),
		flagSet.BoolVar(&randomUserAgent, "random-agent", true, "enable Random User-Agent to use"),
		flagSet.IntVar(&retries, "retries", 5, "number of retries, if status code is 429"),
	)
	flagSet.CreateGroup("debug", "DEBUG",
		flagSet.BoolVarP(&verbose, "verbose", "v", false, "verbose mode"),
		flagSet.BoolVarP(&silent, "silent", "s", false, "silent mode (default true)"),
	)

	_ = flagSet.Parse()

	// cConcurrency = cConcurrency * 100

	// Initialize http.Client once
	timeout := time.Duration(to) * time.Second // Replace with your timeout value
	httpClient = &http.Client{
		Transport: &http.Transport{
			MaxConnsPerHost:     cConcurrency,     // Adjust as needed
			MaxIdleConns:        cConcurrency,     // Adjust as needed
			MaxIdleConnsPerHost: cConcurrency / 2, // Adjust as needed
			IdleConnTimeout:     30 * time.Second,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if followRedirect {
				// Always allow redirects
				return nil
			} else {
				// Don't follow redirects
				return http.ErrUseLastResponse
			}
		},
	}

	// User-Agent list
	userAgents = []string{
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

// //New add
// func wConcurrency(batches <-chan batch, results chan<- result, wg *sync.WaitGroup) {
//     defer wg.Done()

//     for batch := range batches {
//         for _, url := range batch.urls {
//             resp, fullURL := mGET(url, batch.word)
//             if resp != nil {
//                 results <- result{url: fullURL, status: resp.StatusCode, contentLen: resp.ContentLength, body: resp}
//             }
//         }
//     }
// }
// //end of it

func wConcurrency(jobs <-chan job, results chan<- result, wg *sync.WaitGroup) {
	defer wg.Done()

	for job := range jobs {
		resp, url := mGET(job.url, job.word)
		if resp != nil {
			results <- result{url: url, status: resp.StatusCode, contentLen: resp.ContentLength, body: resp}
		}
		/* else {
			// Will handle the error later
		} */
	}
}

func getRandomUserAgent() string {
	// Select a random User-Agent from the list
	return userAgents[rand.Intn(len(userAgents))]
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

func matchRespTitle(body []byte, titles []string) bool {
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

func detectMatch(fullURL string, resp *http.Response) bool {
	// check if input matchStrings(s) have been provided
	if resp.StatusCode == http.StatusOK && len(matchStrings) > 0 {
		body, err := readResponseBody(resp)
		if err != nil {
			silentModeEr(silent, fullURL, err)
			return false
		}

		bodyReader := bytes.NewReader(body)
		bodyTitle, err := goquery.NewDocumentFromReader(bodyReader)
		if err != nil {
			silentModeEr(silent, fullURL, err)
			return false
		}

		title := bodyTitle.Find("title").Text()
		responseText := bodyTitle.Text()

		if matchRespTitle([]byte(responseText), matchStrings) || matchRespTitle([]byte(title), matchStrings) {
			return true
		} else {
			return false
		}
	}
	return false
}

func mGET(url string, word string) (*http.Response, string) {
	var fullURL string
	urls, err := neturl.Parse(url)
	if err != nil {
		gologger.Error().Msgf(Red + "Invalid URL: " + url + Reset)
		return nil, fullURL
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

	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		silentModeEr(silent, fullURL, err)
		return nil, fullURL
	}

	// Set User-Agent header
	if randomUserAgent {
		req.Header.Set("User-Agent", getRandomUserAgent())
	} else {
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		silentModeEr(silent, fullURL, err)
		return nil, fullURL
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		retryAttempts := 0
		maxRetries := retries
		for retryAttempts < maxRetries {
			retryAttempts++
			// Exponential backoff: wait for 2^retryAttempts seconds before retrying
			backoffDuration := time.Duration(2<<retryAttempts+1) * time.Second
			// log.Printf(Yellow+"Received 429 Too Many Requests. Retrying in %v seconds..."+Reset, backoffDuration.Seconds())
			time.Sleep(backoffDuration)
			resp, err := httpClient.Do(req)
			if err != nil {
				silentModeEr(silent, fullURL, err)
				return nil, fullURL
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusTooManyRequests {
				break
			}
		}
		if resp.StatusCode == http.StatusTooManyRequests {
			silentModeEr(silent, fullURL, errors.New("429 TooManyRequests"))
			return nil, fullURL
		}
	}
	if len(matchStrings) > 0 {
		// Read the response body into a variable before closing
		body, err := readResponseBody(resp)
		if err != nil {
			silentModeEr(silent, fullURL, err)
			return nil, fullURL
		}

		// Close the original response body
		resp.Body.Close()

		// Create a new response with the body
		newResp := &http.Response{
			Status:        resp.Status,
			StatusCode:    resp.StatusCode,
			Header:        resp.Header,
			Body:          ioutil.NopCloser(bytes.NewReader(body)),
			ContentLength: resp.ContentLength,
		}
		return newResp, fullURL
	}

	return resp, fullURL
}

// // new code
// func readUrlFromFile(wordlist string, urlFilename string, urls *[]string) error {
//     file, err := os.Open(urlFilename)
//     if err != nil {
//         return err
//     }
//     defer file.Close()

//     scanner := bufio.NewScanner(file)
//     for scanner.Scan() {
//         url := scanner.Text()
//         *urls = append(*urls, url)
//     }

//     if err := scanner.Err(); err != nil {
//         return err
//     }

//     return nil
// }
// // end of it

func readUrlFromFile(wordlist string, urlFilename string, jobs chan<- job) error {
	file, err := os.Open(urlFilename)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		url := scanner.Text()
		jobs <- job{url: url, word: wordlist}
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	return nil
}

func verboseMode(verbose bool, status int, url string, contentLen int64) {
	if verbose && status != 0 {
		gologger.Print().Msgf(Red+"%d -> %s -> %d"+Reset, status, url, contentLen)
	}
}

func silentModeEr(silent bool, urlStr string, message error) {
	if silent {
		gologger.Error().Msgf("Error making GET request to %s: %v", urlStr, message)
	}
}

func main() {
	startTime := time.Now()
	gologger.Info().Msg("dfuzz is running...")
	if len(matchStrings) > 0 {
		gologger.Info().Msgf("Match Title : "+Yellow+"Enable %v"+Reset, matchStrings)
	} else {
		gologger.Info().Msgf(Yellow + "Running In Defaul Mode" + Reset)
	}

	if wordlistFile == "" || urlFile == "" {
		gologger.Fatal().Msgf(Red + "Please specify wordlist and target using -w/-wordlist and -l" + Reset)
	}

	if !strings.HasSuffix(wordlistFile, ".txt") || !strings.HasSuffix(urlFile, ".txt") {
		gologger.Fatal().Msgf(Red + "Wordlist and target files must have .txt extension." + Reset)
	}

	// Seting the BufferSize by using cConcurrency
	jobBufferSize := cConcurrency * 10       // Increased buffer size
	resultBufferSize := cConcurrency*10 + 10 // Limit the number of results stored in memory

	jobs := make(chan job, jobBufferSize)          // Increased buffer size
	results := make(chan result, resultBufferSize) // Limit the number of results in memory
	var wg sync.WaitGroup

	// // DEBUGGING THE cConcurrency
	// fmt.Println(cConcurrency)
	// fmt.Println(jobBufferSize)
	// fmt.Println(resultBufferSize)

	// DEBUGING ERROR MSG
	// n := errors.New("429 TooMuchRes")
	// fmt.Println(n)
	// os.Exit(1)
	/* //DEBUG THE TIMEOUT
	// fmt.Println(20000000000 * time.Nanosecond)
	// fmt.Println(20000000000 * time.Microsecond)
	fmt.Println(time.Duration(20)*time.Second)
	timeout := time.Duration(to)*time.Second // Replace with your timeout value
	fmt.Println(timeout) */
	// os.Exit(1)

	// Start workers
	for i := 0; i < cConcurrency; i++ {
		wg.Add(1)
		go wConcurrency(jobs, results, &wg)
	}

	// Read wordlist from file
	wordlistFile, err := os.Open(wordlistFile)
	if err != nil {
		gologger.Fatal().Msgf("Error opening wordlist file: %v\n", err)
		return
	}
	defer wordlistFile.Close()

	// File to save URLs with status code 200
	var successFile *os.File
	if outputFile != "" {
		successFile, err = os.Create(outputFile)
		if err != nil {
			gologger.Fatal().Msgf("Error creating success file: %v\n", err)
		}
		defer successFile.Close()
	}

	// Start a goroutine to handle results concurrently
	go func() {
		for result := range results {
			if result.status == http.StatusOK && successFile != nil && len(matchStrings) == 0 {
				// Save the URL to the success file
				_, err := fmt.Fprintf(successFile, "%s\n", result.url)
				if err != nil {
					gologger.Fatal().Msgf("Error writing to success file: %v\n", err)
				}
				gologger.Print().Msgf(Blue+"%d -> %s -> %d"+Reset, result.status, result.url, result.contentLen)
			} else if result.status != http.StatusOK && successFile != nil && len(matchStrings) == 0 && verbose {
				verboseMode(verbose, result.status, result.url, result.contentLen)
			} else if len(matchStrings) > 0 {
				if detectMatch(result.url, result.body) {
					if successFile != nil {
						// Save the URL to the success file
						_, err := fmt.Fprintf(successFile, "%s\n", result.url)
						if err != nil {
							gologger.Fatal().Msgf("Error writing to success file: %v\n", err)
						}
						gologger.Print().Msgf(Blue+"Matched Title Detected -> %s "+Reset, result.url)
					} else {
						gologger.Print().Msgf(Blue+"Matched Title Detected -> %s "+Reset, result.url)
					}
				} else {
					if successFile != nil {
						verboseMode(verbose, result.status, result.url, result.contentLen)
					} else {
						verboseMode(verbose, result.status, result.url, result.contentLen)
					}
				}
			} else if result.status == http.StatusOK && len(matchStrings) == 0 && successFile == nil {
				gologger.Print().Msgf(Blue+"%d -> %s -> %d"+Reset, result.status, result.url, result.contentLen)
			} else if result.status != http.StatusOK && len(matchStrings) == 0 && successFile == nil && verbose {
				verboseMode(verbose, result.status, result.url, result.contentLen)
			}
		}
	}()

	wordlistScanner := bufio.NewScanner(wordlistFile)
	for wordlistScanner.Scan() {
		wordlist := wordlistScanner.Text()

		// Read URLs from file and send jobs to the channel
		if err := readUrlFromFile(wordlist, urlFile, jobs); err != nil {
			gologger.Fatal().Msgf("Error reading URL from file: %v\n", err)
			return
		}
	}

	// Close the jobs channel after all wordlists and URLs have been processed
	close(jobs)

	// Wait for the workers to finish processing
	wg.Wait()

	// Close the results channel
	close(results)

	elapsedTime := time.Since(startTime)
	gologger.Info().Msgf("Total time taken: "+Cyan+"%s"+Reset, elapsedTime)
}

// //New add
// func main() {
//     startTime := time.Now()
//     gologger.Info().Msg("dfuzz is running...")
//     if len(matchStrings) > 0 {
//         gologger.Info().Msgf("Match Title : " + Yellow + "Enable %v" + Reset, matchStrings)
//     } else {
//         gologger.Info().Msgf(Yellow + "Running In Defaul Mode" + Reset)
//     }

//     if wordlistFile == "" || urlFile == "" {
//         gologger.Fatal().Msgf(Red + "Please specify wordlist and target using -w/-wordlist and -l" + Reset)
//     }

//     if !strings.HasSuffix(wordlistFile, ".txt") || !strings.HasSuffix(urlFile, ".txt") {
//         gologger.Fatal().Msgf(Red + "Wordlist and target files must have .txt extension." + Reset)
//     }

//     // Seting the BufferSize by using cConcurrency
//     jobBufferSize := cConcurrency * 5        // Increased buffer size
//     resultBufferSize := cConcurrency*10 + 10 // Limit the number of results stored in memory

//     // jobs := make(chan job, jobBufferSize)          // Increased buffer size
//     results := make(chan result, resultBufferSize) // Limit the number of results in memory
//     batches := make(chan batch, cConcurrency)       // Channel for batches
//     var wg sync.WaitGroup

//     // DEBUGGING THE cConcurrency
//     fmt.Println(cConcurrency)
//     fmt.Println(jobBufferSize)
//     fmt.Println(resultBufferSize)

//     // DEBUGING ERROR MSG
//     // n := errors.New("429 TooMuchRes")
//     // fmt.Println(n)
//     // os.Exit(1)
//     /* //DEBUG THE TIMEOUT
//     // fmt.Println(20000000000 * time.Nanosecond)
//     // fmt.Println(20000000000 * time.Microsecond)
//     fmt.Println(time.Duration(20)*time.Second)
//     timeout := time.Duration(to)*time.Second // Replace with your timeout value
//     fmt.Println(timeout) */
//     // os.Exit(1)

//     // Start workers
//     for i := 0; i < cConcurrency; i++ {
//         wg.Add(1)
//         go wConcurrency(batches, results, &wg)
//     }

//     // Read wordlist from file
//     wordlistFile, err := os.Open(wordlistFile)
//     if err != nil {
//         gologger.Fatal().Msgf("Error opening wordlist file: %v\n", err)
//         return
//     }
//     defer wordlistFile.Close()

//     // File to save URLs with status code 200
//     var successFile *os.File
//     if outputFile != "" {
//         successFile, err = os.Create(outputFile)
//         if err != nil {
//             gologger.Fatal().Msgf("Error creating success file: %v\n", err)
//         }
//         defer successFile.Close()
//     }

//     // Start a goroutine to handle results concurrently
//     go func() {
//         for result := range results {
//             if result.status == http.StatusOK && successFile != nil && len(matchStrings) == 0 {
//                 // Save the URL to the success file
//                 _, err := fmt.Fprintf(successFile, "%s\n", result.url)
//                 if err != nil {
//                     gologger.Fatal().Msgf("Error writing to success file: %v\n", err)
//                 }
//                 gologger.Print().Msgf(Blue+"%d -> %s -> %d"+Reset, result.status, result.url, result.contentLen)
//             } else if result.status != http.StatusOK && successFile != nil && len(matchStrings) == 0 && verbose {
//                 verboseMode(verbose, result.status, result.url, result.contentLen)
//             } else if len(matchStrings) > 0 {
//                 if detectMatch(result.url, result.body) {
//                     if successFile != nil {
//                         // Save the URL to the success file
//                         _, err := fmt.Fprintf(successFile, "%s\n", result.url)
//                         if err != nil {
//                             gologger.Fatal().Msgf("Error writing to success file: %v\n", err)
//                         }
//                         gologger.Print().Msgf(Blue+"Matched Title Detected -> %s "+Reset, result.url)
//                     } else {
//                         gologger.Print().Msgf(Blue+"Matched Title Detected -> %s "+Reset, result.url)
//                     }
//                 } else {
//                     if successFile != nil {
//                         verboseMode(verbose, result.status, result.url, result.contentLen)
//                     } else {
//                         verboseMode(verbose, result.status, result.url, result.contentLen)
//                     }
//                 }
//             } else if result.status == http.StatusOK && len(matchStrings) == 0 && successFile == nil {
//                 gologger.Print().Msgf(Blue+"%d -> %s -> %d"+Reset, result.status, result.url, result.contentLen)
//             } else if result.status != http.StatusOK && len(matchStrings) == 0 && successFile == nil && verbose {
//                 verboseMode(verbose, result.status, result.url, result.contentLen)
//             }
//         }
//     }()

//     wordlistScanner := bufio.NewScanner(wordlistFile)
//     for wordlistScanner.Scan() {
//         wordlist := wordlistScanner.Text()

//         // Read URLs from file and create batches
//         var urls []string
//         if err := readUrlFromFile(wordlist, urlFile, &urls); err != nil {
//             gologger.Fatal().Msgf("Error reading URL from file: %v\n", err)
//             return
//         }

//         // Split the URLs into batches (e.g., batches of 10 URLs)
//         batchSize := 500
//         for i := 0; i < len(urls); i += batchSize {
//             end := i + batchSize
//             if end > len(urls) {
//                 end = len(urls)
//             }

//             // Send a batch to the workers
//             batches <- batch{urls: urls[i:end], word: wordlist}
//         }
//     }

//     // Close the batches channel after all wordlists and URLs have been processed
//     close(batches)

//     // Wait for the workers to finish processing
//     wg.Wait()

//     // Close the results channel
//     close(results)

//     elapsedTime := time.Since(startTime)
//     gologger.Info().Msgf("Total time taken: " + Cyan + "%s" + Reset, elapsedTime)
// }

// // End of it
