package services

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestSetEntriesSkipsBlankAndCommentLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "entries")
	content := "\n# comment\n /api/v2.0/projects \n\n/api/v2.0/other\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	got, err := SetEntries(path)
	if err != nil {
		t.Fatalf("SetEntries() error = %v", err)
	}

	want := []string{"/api/v2.0/projects", "/api/v2.0/other"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("SetEntries() = %#v, want %#v", got, want)
	}
}

func TestSetEntriesReturnsMissingFileError(t *testing.T) {
	_, err := SetEntries(filepath.Join(t.TempDir(), "missing"))
	if err == nil {
		t.Fatal("expected missing entries file error")
	}
}
