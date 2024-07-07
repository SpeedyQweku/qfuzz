package opt

import (
	"strconv"
	"strings"

	"github.com/projectdiscovery/gologger"

	"github.com/SpeedyQweku/qfuzz/pkg/config"
)


// Print out match responses, then store the outcome to a file.
func MatchPrintOut(result *config.Result, mSCodes, mCSize string) {
	mCSize_int64, _ := strconv.ParseInt(mCSize, 10, 64)
	statusConditions := (result.StatusCode >= 200 && result.StatusCode <= 299) ||
		result.StatusCode == 301 || result.StatusCode == 302 ||
		result.StatusCode == 307 || result.StatusCode == 401 ||
		result.StatusCode == 403 || result.StatusCode == 405 ||
		result.StatusCode == 500

	if statusConditions && len(config.Cfg.MatchStatus) == 0 && len(config.Cfg.MatchContentSize) == 0 && len(config.Cfg.MatchStrings) == 0 {
		gologger.Print().Msgf("\r\033[K%s %s[ContentSize: %d, Status: %v]%s", result.URL, config.Cyan, result.ContentSize, result.Status, config.Reset)
		// Save the URL To the success file
		SaveSfile(result.URL)

		// When just MatchStatus is not called
	} else if len(config.Cfg.MatchStatus) == 0 && len(config.Cfg.MatchContentSize) != 0 && len(config.Cfg.MatchStrings) != 0 {
		if mSCodes == "all" || result.ContentSize == mCSize_int64 || result.Match {
			gologger.Print().Msgf("\r\033[K%s %s[ContentSize: %d, Status: %v]%s", result.URL, config.Cyan, result.ContentSize, result.Status, config.Reset)
			// Save the URL To the success file
			SaveSfile(result.URL)
		}

		// When just MatchStrings is called
	} else if len(config.Cfg.MatchStatus) == 0 && len(config.Cfg.MatchContentSize) == 0 && len(config.Cfg.MatchStrings) != 0 {
		if mSCodes == "all" || !(result.ContentSize == mCSize_int64) && result.Match {
			gologger.Print().Msgf("\r\033[K%s %s[ContentSize: %d, Status: %v]%s", result.URL, config.Cyan, result.ContentSize, result.Status, config.Reset)
			// Save the URL To the success file
			SaveSfile(result.URL)
		}

		// When just MatchContentSize is called
	} else if len(config.Cfg.MatchStatus) == 0 && len(config.Cfg.MatchContentSize) != 0 && len(config.Cfg.MatchStrings) == 0 {
		if mSCodes == "all" || result.ContentSize == mCSize_int64 && !(result.Match) {
			gologger.Print().Msgf("\r\033[K%s %s[ContentSize: %d, Status: %v]%s", result.URL, config.Cyan, result.ContentSize, result.Status, config.Reset)
			// Save the URL To the success file
			SaveSfile(result.URL)
		}

		// When all are Matcher and called
	} else if len(config.Cfg.MatchStatus) != 0 && len(config.Cfg.MatchContentSize) != 0 && len(config.Cfg.MatchStrings) != 0 {
		if (strings.Contains(result.Status, mSCodes) || mSCodes == "all") || result.ContentSize == mCSize_int64 || result.Match {
			gologger.Print().Msgf("\r\033[K%s %s[ContentSize: %d, Status: %v]%s", result.URL, config.Cyan, result.ContentSize, result.Status, config.Reset)
			// Save the URL To the success file
			SaveSfile(result.URL)
		}

		// When MatchStrings in not called
	} else if len(config.Cfg.MatchStatus) != 0 && len(config.Cfg.MatchContentSize) != 0 && len(config.Cfg.MatchStrings) == 0 {
		if (strings.Contains(result.Status, mSCodes) || mSCodes == "all") || result.ContentSize == mCSize_int64 && !(result.Match) {
			gologger.Print().Msgf("\r\033[K%s %s[ContentSize: %d, Status: %v]%s", result.URL, config.Cyan, result.ContentSize, result.Status, config.Reset)
			// Save the URL To the success file
			SaveSfile(result.URL)
		}

		// When just MatchStatus is called
	} else if len(config.Cfg.MatchStatus) != 0 && len(config.Cfg.MatchContentSize) == 0 && len(config.Cfg.MatchStrings) == 0 {
		if (strings.Contains(result.Status, mSCodes) || mSCodes == "all") && !(result.ContentSize == mCSize_int64 && result.Match) {
			gologger.Print().Msgf("\r\033[K%s %s[ContentSize: %d, Status: %v]%s", result.URL, config.Cyan, result.ContentSize, result.Status, config.Reset)
			// Save the URL To the success file
			SaveSfile(result.URL)
		}

		// When just MatchContentSize is not called
	} else if len(config.Cfg.MatchStatus) != 0 && len(config.Cfg.MatchContentSize) == 0 && len(config.Cfg.MatchStrings) != 0 {
		if (strings.Contains(result.Status, mSCodes) || mSCodes == "all") || result.Match && !(result.ContentSize == mCSize_int64) {
			gologger.Print().Msgf("\r\033[K%s %s[ContentSize: %d, Status: %v]%s", result.URL, config.Cyan, result.ContentSize, result.Status, config.Reset)
			// Save the URL To the success file
			SaveSfile(result.URL)
		}
	}
}

// filter responses and print the rest then store the outcofe to a file.
func FilterPrintOut(result *config.Result, fSCodes, fCSize string) {
	fCSize_int64, _ := strconv.ParseInt(fCSize, 10, 64)
	statusConditions := (result.StatusCode >= 200 && result.StatusCode <= 299) ||
		result.StatusCode == 301 || result.StatusCode == 302 ||
		result.StatusCode == 307 || result.StatusCode == 401 ||
		result.StatusCode == 403 || result.StatusCode == 405 ||
		result.StatusCode == 500

	if statusConditions && len(config.Cfg.FilterStatus) == 0 && len(config.Cfg.FilterContentSize) != 0 && len(config.Cfg.FilterStrings) != 0 {
		if !(strings.Contains(result.Status, fSCodes) && fSCodes == "all") || result.ContentSize == fCSize_int64 || result.Match {
			return
		} else {
			gologger.Print().Msgf("\r\033[K%s %s[ContentSize: %d, Status: %v]%s", result.URL, config.Cyan, result.ContentSize, result.Status, config.Reset)
			// Save the URL To the success file
			SaveSfile(result.URL)
		}
	} else if statusConditions && len(config.Cfg.FilterStatus) == 0 && len(config.Cfg.FilterContentSize) == 0 && len(config.Cfg.FilterStrings) != 0 {
		if !(strings.Contains(result.Status, fSCodes) && fSCodes == "all") && !(result.ContentSize == fCSize_int64) && result.Match {
			return
		} else {
			gologger.Print().Msgf("\r\033[K%s %s[ContentSize: %d, Status: %v]%s", result.URL, config.Cyan, result.ContentSize, result.Status, config.Reset)
			// Save the URL To the success file
			SaveSfile(result.URL)
		}
	} else if statusConditions && len(config.Cfg.FilterStatus) == 0 && len(config.Cfg.FilterContentSize) != 0 && len(config.Cfg.FilterStrings) == 0 {
		if !(strings.Contains(result.Status, fSCodes) && fSCodes == "all") && result.ContentSize == fCSize_int64 && !(result.Match) {
			return
		} else {
			gologger.Print().Msgf("\r\033[K%s %s[ContentSize: %d, Status: %v]%s", result.URL, config.Cyan, result.ContentSize, result.Status, config.Reset)
			// Save the URL To the success file
			SaveSfile(result.URL)

		}
	} else if statusConditions && len(config.Cfg.FilterStatus) != 0 && len(config.Cfg.FilterContentSize) != 0 && len(config.Cfg.FilterStrings) != 0 { // When all are Matcher and called
		if (strings.Contains(result.Status, fSCodes) || fSCodes == "all") || result.ContentSize == fCSize_int64 || result.Match {
			return
		} else {
			gologger.Print().Msgf("\r\033[K%s %s[ContentSize: %d, Status: %v]%s", result.URL, config.Cyan, result.ContentSize, result.Status, config.Reset)
			// Save the URL To the success file
			SaveSfile(result.URL)

		}
	} else if statusConditions && len(config.Cfg.FilterStatus) != 0 && len(config.Cfg.FilterContentSize) != 0 && len(config.Cfg.FilterStrings) == 0 { // When FilterStrings in not called
		if (strings.Contains(result.Status, fSCodes) || fSCodes == "all") || result.ContentSize == fCSize_int64 && !(result.Match) {
			return
		} else {
			gologger.Print().Msgf("\r\033[K%s %s[ContentSize: %d, Status: %v]%s", result.URL, config.Cyan, result.ContentSize, result.Status, config.Reset)
			// Save the URL To the success file
			SaveSfile(result.URL)

		}
	} else if statusConditions && len(config.Cfg.FilterStatus) != 0 && len(config.Cfg.FilterContentSize) == 0 && len(config.Cfg.FilterStrings) == 0 { // When just FilterStatus is called
		if (strings.Contains(result.Status, fSCodes) || fSCodes == "all") && !(result.ContentSize == fCSize_int64 && result.Match) {
			return
		} else {
			gologger.Print().Msgf("\r\033[K%s %s[ContentSize: %d, Status: %v]%s", result.URL, config.Cyan, result.ContentSize, result.Status, config.Reset)
			// Save the URL To the success file
			SaveSfile(result.URL)

		}
	} else if statusConditions && len(config.Cfg.FilterStatus) != 0 && len(config.Cfg.FilterContentSize) == 0 && len(config.Cfg.FilterStrings) != 0 { // When just FilterContentSize is not called
		if (strings.Contains(result.Status, fSCodes) || fSCodes == "all") && !(result.ContentSize == fCSize_int64) || result.Match {
			return
		} else {
			gologger.Print().Msgf("\r\033[K%s %s[ContentSize: %d, Status: %v]%s", result.URL, config.Cyan, result.ContentSize, result.Status, config.Reset)
			// Save the URL To the success file
			SaveSfile(result.URL)
		}
	}
}
