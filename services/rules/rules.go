package services

import (
	"bufio"
	"os"
	"strings"
)

const APIEntriesPath = "./apis/entries"

func SetEntries(path string) (rules []string, err error) {
	rules, err = readFile(path)
	return
}

func readFile(path string) (lines []string, err error) {
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	err = scanner.Err()
	return
}
