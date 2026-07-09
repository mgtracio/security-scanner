package services

import "testing"

func TestParseNormalizesBaseAndPath(t *testing.T) {
	got := Parse(" https://harbor.example.com/ ", " /api/v2.0/projects ")

	if got.Base != "https://harbor.example.com" {
		t.Fatalf("Base = %q, want %q", got.Base, "https://harbor.example.com")
	}
	if got.Path != "/api/v2.0/projects" {
		t.Fatalf("Path = %q, want %q", got.Path, "/api/v2.0/projects")
	}
	if got.Full != "https://harbor.example.com/api/v2.0/projects" {
		t.Fatalf("Full = %q", got.Full)
	}
}
