package opt

import (
	"fmt"
	neturl "net/url"
	"os"
	"strings"

	"github.com/projectdiscovery/gologger"
	"github.com/schollz/progressbar/v3"

	// "github.com/SpeedyQweku/qfuzz/pkg/common"
	"github.com/SpeedyQweku/qfuzz/pkg/config"
	// "github.com/SpeedyQweku/qfuzz/pkg/mkreq"
	// "github.com/SpeedyQweku/qfuzz/pkg/output"
)

// var (
// 	cfg config.Config
// 	// mu  sync.Mutex
// 	// result config.Result
// )


// processUrls process the urls
func ProcessUrls(url, word string, cfg config.Config) string {
	var fullURL string

	urls, err := neturl.Parse(url)
	if err != nil {
		gologger.Error().Msgf(config.Red + "Invalid URL: " + url + config.Reset)
		// return
	}
	if urls.Scheme == "" {
		urls.Scheme = "https"
	}

	if strings.HasPrefix(word, "/") {
		word = strings.TrimLeft(word, "/")
	}

	if strings.Contains(config.Cfg.PostData, "FUZZ") || CheckFUZZheader(config.Cfg.Headers) {
		// fmt.Println(config.Cfg.PostData)
		fullURL = urls.String()
		// } else if headerFUZZcheck(config.Cfg.Headers) {
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

// Save the URL To the success file
func SaveSfile(url string) {
	if len(config.Cfg.OutputFile) != 0 {
		if config.Cfg.SuccessFile != nil {
			_, err := fmt.Fprintf(config.Cfg.SuccessFile, "%s\n", url)
			if err != nil {
				gologger.Fatal().Msgf("Error writing To success file: %v\n", err)
			}
		}
	} else {
		return
	}
}

// validateConfig performs initial validation on the configuration
func ValidateConfig() {
	// Validate status codes and sizes
	var statusList []interface{}
	for _, status := range config.Cfg.MatchStatus {
		if status == "all" {
			break
		} else {
			statusList = append(statusList, status)
		}
	}
	for _, status := range config.Cfg.FilterStatus {
		if status == "all" {
			break
		} else {
			statusList = append(statusList, status)
		}
	}
	if !CheckNumber(statusList) {
		gologger.Fatal().Msgf("Invalid value: %v, For -fc/-mc", statusList)
	}

	var sizeList []interface{}
	for _, size := range config.Cfg.MatchContentSize {
		sizeList = append(sizeList, size)
	}
	for _, size := range config.Cfg.FilterContentSize {
		sizeList = append(sizeList, size)
	}
	if !CheckNumber(sizeList) {
		gologger.Fatal().Msgf("Invalid value: %v, For -fl/-ml", sizeList)
	}

	// Check necessary configurations
	if !config.Cfg.WebCache {
		if config.Cfg.WordlistFile == "" && (config.Cfg.UrlFile == "" && len(config.Cfg.UrlString) == 0) {
			gologger.Fatal().Msgf(config.Red + "Please specify wordlist and target using -w/-wordlist, -l or -u" + config.Reset)
		} else if config.Cfg.WordlistFile == "" {
			gologger.Fatal().Msgf(config.Red + "Please specify target using -w/-wordlist" + config.Reset)
		} else if config.Cfg.UrlFile == "" && len(config.Cfg.UrlString) == 0 {
			gologger.Fatal().Msgf(config.Red + "Please specify target using -l or -u" + config.Reset)
		}
	} else {
		if config.Cfg.UrlFile == "" && len(config.Cfg.UrlString) == 0 {
			gologger.Fatal().Msgf(config.Red + "Please specify target using -l or -u" + config.Reset)
		}
	}

	if !config.Cfg.WebCache {
		if !strings.HasSuffix(config.Cfg.WordlistFile, ".txt") || (!strings.HasSuffix(config.Cfg.UrlFile, ".txt") && len(config.Cfg.UrlString) == 0) {
			gologger.Fatal().Msgf(config.Red + "Wordlist and target files must have .txt extension." + config.Reset)
		}
	} else {
		if !strings.HasSuffix(config.Cfg.UrlFile, ".txt") && len(config.Cfg.UrlString) == 0 {
			gologger.Fatal().Msgf(config.Red + "Target file must have .txt extension." + config.Reset)
		}
	}
	if config.Cfg.Concurrency == 0 {
		gologger.Fatal().Msgf("%s-c Can't Be 0%s", config.Red, config.Reset)
	}
	if (len(config.Cfg.MatchStatus) != 0 || len(config.Cfg.MatchStrings) != 0 || len(config.Cfg.MatchContentSize) != 0) && (len(config.Cfg.FilterStatus) != 0 || len(config.Cfg.FilterStrings) != 0 || len(config.Cfg.FilterContentSize) != 0) {
		gologger.Fatal().Msgf("%sCan't run any of the Match(s) and Filter(s) at the same time now%s", config.Red, config.Reset)
	}
}

// progbar initializes and returns a new progress bar with the specified number of steps
func Progbar(progNum int) *progressbar.ProgressBar {
	if !config.Cfg.Silent {
		gologger.Print().Msgf("%s %s", config.Banner, config.Version)
		if config.Cfg.HttpMethod == "" {
			gologger.Info().Msgf("HTTP Method : %s[GET]%s", config.Yellow, config.Reset)
		} else {
			gologger.Info().Msgf("HTTP Method : %s[%s]%s", config.Yellow, strings.ToUpper(config.Cfg.HttpMethod), config.Reset)
		}
		gologger.Info().Msgf("Follow redirects : %s%v%s", config.Yellow, config.Cfg.FollowRedirect, config.Reset)

		if len(config.Cfg.MatchStatus) == 0 && len(config.Cfg.MatchStrings) == 0 && len(config.Cfg.MatchContentSize) == 0 || (len(config.Cfg.FilterStrings) != 0 || len(config.Cfg.FilterContentSize) != 0 || len(config.Cfg.FilterStatus) != 0) {
			gologger.Info().Msgf("Match Status Code : %s[200-299,301,302,307,401,403,405,500]%s", config.Yellow, config.Reset)
		} else if len(config.Cfg.MatchStatus) != 0 {
			gologger.Info().Msgf("Match Status Code : %s%v%s", config.Yellow, config.Cfg.MatchStatus, config.Reset)
		}
		if len(config.Cfg.MatchStrings) != 0 {
			gologger.Info().Msgf("Match Strings : %s%v%s", config.Yellow, config.Cfg.MatchStrings, config.Reset)
		}
		if len(config.Cfg.MatchContentSize) != 0 {
			gologger.Info().Msgf("Match ContentSize : %s%v%s", config.Yellow, config.Cfg.MatchContentSize, config.Reset)
		}
		if len(config.Cfg.FilterStatus) != 0 {
			gologger.Info().Msgf("Filter Status Code : %s%v%s", config.Yellow, config.Cfg.FilterStatus, config.Reset)
		}
		if len(config.Cfg.FilterStrings) != 0 {
			gologger.Info().Msgf("Filter Strings : %s%v%s", config.Yellow, config.Cfg.FilterStrings, config.Reset)
		}
		if len(config.Cfg.FilterContentSize) != 0 {
			gologger.Info().Msgf("Filter ContentSize : %s%v%s", config.Yellow, config.Cfg.FilterContentSize, config.Reset)
		}
		if config.Cfg.WebCache {
			gologger.Info().Msgf("Detect Web Cache : %sEnabled%s", config.Yellow, config.Reset)
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

// processResult handles the result of an HTTP request
func ProcessResult(result *config.Result, cfg config.Config) {
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
		MatchPrintOut(result, mS, mCS)
	} else if len(cfg.MatchStrings) != 0 && len(cfg.MatchStatus) == 0 && len(cfg.MatchContentSize) == 0 && zeroF {
		MatchPrintOut(result, mS, mCS)
	} else if len(cfg.MatchStatus) != 0 && len(cfg.MatchStrings) == 0 && len(cfg.MatchContentSize) == 0 && zeroF {
		for _, mSCodes := range mSCode {
			MatchPrintOut(result, mSCodes, mCS)
		}
	} else if len(cfg.MatchStatus) != 0 && len(cfg.MatchStrings) != 0 && len(cfg.MatchContentSize) == 0 && zeroF {
		for _, mSCodes := range mSCode {
			MatchPrintOut(result, mSCodes, mCS)
		}
	} else if len(cfg.MatchStatus) == 0 && len(cfg.MatchStrings) != 0 && len(cfg.MatchContentSize) != 0 && zeroF {
		for _, mCSizes := range mCSize {
			MatchPrintOut(result, mS, mCSizes)
		}
	} else if len(cfg.MatchStatus) == 0 && len(cfg.MatchStrings) == 0 && len(cfg.MatchContentSize) != 0 && zeroF {
		for _, mCSizes := range mCSize {
			MatchPrintOut(result, mS, mCSizes)
		}
	} else if len(cfg.MatchStatus) != 0 && len(cfg.MatchContentSize) != 0 && len(cfg.MatchStrings) == 0 && zeroF {
		for _, mSCodes := range mSCode {
			for _, mCSizes := range mCSize {
				MatchPrintOut(result, mSCodes, mCSizes)
			}
		}
	} else if len(cfg.MatchStatus) != 0 && len(cfg.MatchContentSize) != 0 && len(cfg.MatchStrings) != 0 && zeroF {
		for _, mSCodes := range mSCode {
			for _, mCSizes := range mCSize {
				MatchPrintOut(result, mSCodes, mCSizes)
			}
		}
	}

	if len(cfg.FilterStrings) != 0 && len(cfg.FilterStatus) == 0 && len(cfg.FilterContentSize) == 0 && zeroM {
		FilterPrintOut(result, fS, fCS)
	} else if len(cfg.FilterStatus) != 0 && len(cfg.FilterStrings) == 0 && len(cfg.FilterContentSize) == 0 && zeroM {
		for _, fSCodes := range fSCode {
			FilterPrintOut(result, fSCodes, fCS)
		}
	} else if len(cfg.FilterStatus) != 0 && len(cfg.FilterStrings) != 0 && len(cfg.FilterContentSize) == 0 && zeroM {
		for _, fSCodes := range fSCode {
			FilterPrintOut(result, fSCodes, fCS)
		}
	} else if len(cfg.FilterStatus) == 0 && len(cfg.FilterStrings) != 0 && len(cfg.FilterContentSize) != 0 && zeroM {
		for _, fCSizes := range fCSize {
			FilterPrintOut(result, fS, fCSizes)
		}
	} else if len(cfg.FilterStatus) == 0 && len(cfg.FilterStrings) == 0 && len(cfg.FilterContentSize) != 0 && zeroM {
		for _, fCSizes := range fCSize {
			FilterPrintOut(result, fS, fCSizes)
		}
	} else if len(cfg.FilterStatus) != 0 && len(cfg.FilterContentSize) != 0 && len(cfg.FilterStrings) == 0 && zeroM {
		for _, fSCodes := range fSCode {
			for _, fCSizes := range fCSize {
				FilterPrintOut(result, fSCodes, fCSizes)
			}
		}
	} else if len(cfg.FilterStatus) != 0 && len(cfg.FilterContentSize) != 0 && len(cfg.FilterStrings) != 0 && zeroM {
		for _, fSCodes := range fSCode {
			for _, fCSizes := range fCSize {
				FilterPrintOut(result, fSCodes, fCSizes)
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
