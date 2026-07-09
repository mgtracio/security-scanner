package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunRejectsNonPositiveTimeout(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	err := run([]string{"-base-url", "https://harbor.example.com", "-timeout", "0s"}, strings.NewReader(""), &stdout, &stderr)
	if err == nil {
		t.Fatal("expected timeout validation error")
	}
	if !strings.Contains(err.Error(), "timeout must be positive") {
		t.Fatalf("error = %q, want timeout validation", err.Error())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty output", stdout.String())
	}
}

func TestRunRejectsNonPositiveConcurrency(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	err := run([]string{"-base-url", "https://harbor.example.com", "-concurrency", "0"}, strings.NewReader(""), &stdout, &stderr)
	if err == nil {
		t.Fatal("expected concurrency validation error")
	}
	if !strings.Contains(err.Error(), "concurrency must be positive") {
		t.Fatalf("error = %q, want concurrency validation", err.Error())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty output", stdout.String())
	}
}

func TestRunRejectsEmptyEntriesFile(t *testing.T) {
	entriesPath := filepath.Join(t.TempDir(), "entries")
	if err := os.WriteFile(entriesPath, []byte("\n# no entries\n"), 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	err := run([]string{"-base-url", "https://harbor.example.com", "-entries", entriesPath}, strings.NewReader(""), &stdout, &stderr)
	if err == nil {
		t.Fatal("expected empty entries validation error")
	}
	if !strings.Contains(err.Error(), "no API entries found") {
		t.Fatalf("error = %q, want empty entries validation", err.Error())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty output", stdout.String())
	}
	if !strings.Contains(stderr.String(), "Scanner - Harbor application scanner.") {
		t.Fatalf("stderr = %q, want scanner banner", stderr.String())
	}
}

func TestRunRejectsInvalidVulnerabilitySeverity(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	err := run([]string{"-base-url", "https://harbor.example.com", "-min-vulnerability-severity", "urgent"}, strings.NewReader(""), &stdout, &stderr)
	if err == nil {
		t.Fatal("expected vulnerability severity validation error")
	}
	if !strings.Contains(err.Error(), "unsupported vulnerability severity") {
		t.Fatalf("error = %q, want severity validation", err.Error())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty output", stdout.String())
	}
}
