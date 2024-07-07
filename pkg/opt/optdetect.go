package opt

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"sync"

	"golang.org/x/net/html"
	"github.com/projectdiscovery/gologger"

	"github.com/SpeedyQweku/qfuzz/pkg/common"
	"github.com/SpeedyQweku/qfuzz/pkg/config"
)

// Check if the HTTP response has a specific string
func DetectBodyMatch(fullURL string, body []byte) bool {
	bodyReader := bytes.NewReader(body)
	doc, err := html.Parse(bodyReader)
	if err != nil {
		common.DebugModeEr(config.Cfg.Debug, fullURL, err)
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
	if len(config.Cfg.MatchStrings) != 0 {
		if MatchRespData([]byte(responseText), config.Cfg.MatchStrings) || MatchRespData([]byte(title), config.Cfg.MatchStrings) {
			return true
		}
	}
	if len(config.Cfg.FilterStrings) != 0 {
		if MatchRespData([]byte(responseText), config.Cfg.FilterStrings) || MatchRespData([]byte(title), config.Cfg.FilterStrings) {
			return true
		}
	}
	return false
}

// detectWebCache identifies if the host is utilizing web caching, and if so, stores it.
func DetectWebCache(key string, vals []string, fullURL string, mu *sync.Mutex) bool {
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
						if config.Cfg.Cachefile == nil {
							file, err := os.OpenFile("discoveredWebCache.txt", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)
							if err != nil {
								gologger.Fatal().Msgf("Error opening WebCache file: %v", err)
							}
							config.Cfg.Cachefile = file
						}
						// Write the URL to the cache file
						_, err := fmt.Fprintf(config.Cfg.Cachefile, "%s\n", fullURL)
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
