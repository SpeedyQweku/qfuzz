package opt

import (
	"strconv"
	"strings"
)

// check if "FUZZ" is in the headers
func CheckFUZZheader(headerData []string) bool {
	for _, item := range headerData {
		if strings.Contains(item, "FUZZ") {
			return true
		}
	}
	return false
}

// check if input(s) are number(s)
func CheckNumber(numbers []interface{}) bool {
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
