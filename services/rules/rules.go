package services

import (
"bufio"
"os"
)

const APIEntriesPath = "./apis/entries"

func SetEntries(path string) (rules []string, err error) {
	rules, err = readFile(path)
	return
}

func readFile(path string) (lines []string, err error) {
	file, err := os.Open(path)
	defer file.Close()
	if err != nil {
		return
	}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	err = scanner.Err()
	return
}
