package jsscanner_test

import (
	"testing"
	"verdamt-engine/pkg/jsscanner"
)

func TestScanFileSecrets(t *testing.T) {
	s := jsscanner.NewScanner()
	content := `
		var google_key = "AIzaSyD12345678901234567890123456789012";
		var aws_key = "AKIAIOSFODNN7EXAMPLE";
		var email = "test@admin.local";
	`
	file := jsscanner.FileInput{
		URL:     "http://example.com/app.js",
		Content: content,
		Status:  200,
		Time:    0.1,
	}

	findings, _ := s.ScanFile(file)
	if len(findings) < 3 {
		t.Fatalf("Expected at least 3 secret findings, got %d", len(findings))
	}
}

func TestScanFileEndpoints(t *testing.T) {
	s := jsscanner.NewScanner()
	content := `
		fetch("/api/v1/users");
		axios.get("/v2/admin/config");
	`
	file := jsscanner.FileInput{
		URL:     "http://example.com/app.js",
		Content: content,
		Status:  200,
		Time:    0.1,
	}

	_, endpoints := s.ScanFile(file)
	if len(endpoints) < 2 {
		t.Fatalf("Expected at least 2 endpoints, got %d", len(endpoints))
	}
}
