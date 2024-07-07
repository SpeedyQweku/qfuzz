package opt

import (
	"bufio"
	"bytes"
	"io"
	"net/http"
	"os"

	"github.com/projectdiscovery/gologger"

	"github.com/SpeedyQweku/qfuzz/pkg/config"
	"github.com/SpeedyQweku/qfuzz/pkg/common"
)


// It reads the response body
func ReadResponseBody(resp *http.Response, fullUrl string) ([]byte, error) {
	var bodyBuffer bytes.Buffer
	_, err := io.Copy(&bodyBuffer, resp.Body)
	if err != nil {
		common.DebugModeEr(config.Cfg.Debug, fullUrl, err)
		return nil, err
	}
	return bodyBuffer.Bytes(), nil
}

// readInputFiles reads the wordlist and URLs from specified files
func ReadInputFiles(cfg config.Config) ([]string, []string) {
	var words, urls []string
	var err error

	if cfg.WordlistFile != "" {
		words, err = ReadLines(cfg.WordlistFile)
		if err != nil {
			gologger.Fatal().Msgf("Error reading wordlist: %v", err)
		}
	}

	if cfg.UrlFile != "" {
		urls, err = ReadLines(cfg.UrlFile)
		if err != nil {
			gologger.Fatal().Msgf("Error reading URLs: %v", err)
		}
	} else if len(cfg.UrlString) != 0 {
		urls = cfg.UrlString
	}

	return words, urls
}

// Reading A File Line By Line
func ReadLines(filename string) ([]string, error) {
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
