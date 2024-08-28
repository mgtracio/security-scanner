package utils

import (
	"fmt"
	"strings"
)

type Key string

func SafeTruncated(str string, v string, safeTruncated string) string {
	pos := strings.Index(strings.ToUpper(str), v)
	var fromPos = pos - 22
	var toPos = pos + 12
	if fromPos < 0 {
		fromPos = 0
	}
	if toPos > len(str) {
		toPos = len(str)
	}
	safeTruncated = fmt.Sprintf("\"%s\"", str[fromPos:toPos])
	return safeTruncated
}

func Contains(str string, s []Key) (b bool, val string) {
	for _, v := range s {
		if strings.Contains(str, string(v)) {
			val = string(v)
			b = true
			return
		}
	}
	return
}
