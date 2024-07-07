package common

import "github.com/projectdiscovery/gologger"

// debugModeEr print out all errors
func DebugModeEr(debug bool, urlStr string, message error) {
	if debug {
		gologger.Error().Msgf("Error %s: %v", urlStr, message)
	}
}
