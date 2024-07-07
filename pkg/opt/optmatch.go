package opt

import "strings"

// to check if respdata contains a string
func MatchRespData(body []byte, raw []string) bool {
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
