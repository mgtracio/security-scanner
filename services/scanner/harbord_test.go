package services

import (
	"bytes"
	"encoding/csv"
	"fmt"
	proxy "github.com/mgtracio/security-scanner/services/http"
	"github.com/mgtracio/security-scanner/services/scanner/entities"
	resource "github.com/mgtracio/security-scanner/services/url"
	"io"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeResponse struct {
	status int
	body   string
}

type fakeHTTPClient struct {
	responses map[string]fakeResponse
}

func (f fakeHTTPClient) Request(url string) (*http.Response, error) {
	response, ok := f.responses[url]
	if !ok {
		return nil, fmt.Errorf("unexpected URL %s", url)
	}

	return &http.Response{
		StatusCode: response.status,
		Body:       io.NopCloser(strings.NewReader(response.body)),
		Header:     make(http.Header),
	}, nil
}

type trackingHTTPClient struct {
	mu        sync.Mutex
	active    int
	maxActive int
	responses map[string]fakeResponse
	delay     time.Duration
}

func (t *trackingHTTPClient) Request(url string) (*http.Response, error) {
	t.mu.Lock()
	t.active++
	if t.active > t.maxActive {
		t.maxActive = t.active
	}
	t.mu.Unlock()

	if t.delay > 0 {
		time.Sleep(t.delay)
	}

	t.mu.Lock()
	t.active--
	t.mu.Unlock()

	response, ok := t.responses[url]
	if !ok {
		return nil, fmt.Errorf("unexpected URL %s", url)
	}
	return &http.Response{
		StatusCode: response.status,
		Body:       io.NopCloser(strings.NewReader(response.body)),
		Header:     make(http.Header),
	}, nil
}

func (t *trackingHTTPClient) MaxActive() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.maxActive
}

func TestScanEndpointReturnsStatusErrorWithResponse(t *testing.T) {
	registryURL := resource.Parse("https://harbor.example.com", "/missing")
	scanner := New(fakeHTTPClient{
		responses: map[string]fakeResponse{
			registryURL.Full: {status: http.StatusNotFound, body: `{"error":"missing"}`},
		},
	}, io.Discard)

	got, err := scanner.ScanEndpoint(registryURL)
	if err == nil {
		t.Fatal("expected status error")
	}
	if got.StatusCode != http.StatusNotFound {
		t.Fatalf("StatusCode = %d, want %d", got.StatusCode, http.StatusNotFound)
	}
	if got.Message != "Not found" {
		t.Fatalf("Message = %q, want Not found", got.Message)
	}
	if got.Body != `{"error":"missing"}` {
		t.Fatalf("Body = %q", got.Body)
	}
}

func TestProcessBuildWritesCSVFinding(t *testing.T) {
	var out bytes.Buffer
	scanner := New(nil, &out)
	registryURL := resource.Parse("https://harbor.example.com", "/api/v2.0/projects")
	buildHistoryURL := resource.Parse("https://harbor.example.com/api/v2.0/projects/library/repositories/team/app/artifacts/sha256:abc", "/additions/build_history")
	response := proxy.HttpResponse{Body: `[{"created_by":"ENV PASSWORD=supersecret"}]`}

	err := scanner.ProcessBuild(
		response,
		buildHistoryURL,
		registryURL,
		entities.Project{Name: "library"},
		entities.Repository{Name: "library/team/app"},
		entities.Artifact{Digest: "sha256:abc"},
		[]string{"v1", "latest"},
	)
	if err != nil {
		t.Fatalf("ProcessBuild() error = %v", err)
	}

	rows := readCSVRows(t, out.String())
	want := [][]string{{
		"https://harbor.example.com",
		"library",
		"team/app",
		"sha256:abc",
		"v1,latest",
		"HIGH",
		"SECRET_ASSIGNMENT PASSWORD=<redacted>",
		"PASSWORD",
		buildHistoryURL.Full,
	}}
	if !reflect.DeepEqual(rows, want) {
		t.Fatalf("CSV rows = %#v, want %#v", rows, want)
	}
	if strings.Contains(out.String(), "supersecret") {
		t.Fatalf("CSV output leaked secret value: %s", out.String())
	}
}

func TestProcessBuildDetectsSecretReferenceWithoutValue(t *testing.T) {
	var out bytes.Buffer
	scanner := New(nil, &out)
	registryURL := resource.Parse("https://harbor.example.com", "/api/v2.0/projects")
	buildHistoryURL := resource.Parse("https://harbor.example.com/api/v2.0/projects/library/repositories/app/artifacts/sha256:abc", "/additions/build_history")
	response := proxy.HttpResponse{Body: `[{"created_by":"ARG GITHUB_TOKEN"}]`}

	err := scanner.ProcessBuild(
		response,
		buildHistoryURL,
		registryURL,
		entities.Project{Name: "library"},
		entities.Repository{Name: "library/app"},
		entities.Artifact{Digest: "sha256:abc"},
		[]string{"latest"},
	)
	if err != nil {
		t.Fatalf("ProcessBuild() error = %v", err)
	}

	rows := readCSVRows(t, out.String())
	if len(rows) != 1 {
		t.Fatalf("row count = %d, want 1: %#v", len(rows), rows)
	}
	if rows[0][5] != "MEDIUM" || rows[0][6] != "SECRET_REFERENCE GITHUB_TOKEN" || rows[0][7] != "GITHUB_TOKEN" {
		t.Fatalf("row = %#v, want medium secret reference", rows[0])
	}
}

func TestProcessBuildIgnoresSensitiveWordWithoutSecretShape(t *testing.T) {
	var out bytes.Buffer
	scanner := New(nil, &out)
	registryURL := resource.Parse("https://harbor.example.com", "/api/v2.0/projects")
	buildHistoryURL := resource.Parse("https://harbor.example.com/api/v2.0/projects/library/repositories/app/artifacts/sha256:abc", "/additions/build_history")
	response := proxy.HttpResponse{Body: `[{"created_by":"RUN echo supersecret"}]`}

	err := scanner.ProcessBuild(
		response,
		buildHistoryURL,
		registryURL,
		entities.Project{Name: "library"},
		entities.Repository{Name: "library/app"},
		entities.Artifact{Digest: "sha256:abc"},
		[]string{"latest"},
	)
	if err != nil {
		t.Fatalf("ProcessBuild() error = %v", err)
	}
	if out.Len() != 0 {
		t.Fatalf("CSV output = %q, want no false-positive finding", out.String())
	}
}

func TestProcessProjectsScansHarborFlow(t *testing.T) {
	var out bytes.Buffer
	registryURL := resource.Parse("https://harbor.example.com", "/api/v2.0/projects")

	scanner := New(fakeHTTPClient{
		responses: map[string]fakeResponse{
			"https://harbor.example.com/api/v2.0/projects/library/repositories": {
				status: http.StatusOK,
				body:   `[{"name":"library/team/app"}]`,
			},
			"https://harbor.example.com/api/v2.0/projects/library/repositories/team%252Fapp/artifacts": {
				status: http.StatusOK,
				body:   `[{"digest":"sha256:abc","tags":[{"name":"v1"}]}]`,
			},
			"https://harbor.example.com/api/v2.0/projects/library/repositories/team%252Fapp/artifacts/sha256:abc/additions/build_history": {
				status: http.StatusOK,
				body:   `[{"created_by":"ENV TOKEN=abc"}]`,
			},
			"https://harbor.example.com/api/v2.0/projects/library/repositories/team%252Fapp/artifacts/sha256:abc/additions/vulnerabilities": {
				status: http.StatusOK,
				body: `{
					"application/vnd.security.vulnerability.report; version=1.1": {
						"scanner": {"name":"Trivy"},
						"severity":"Critical",
						"vulnerabilities": [
							{
								"id":"CVE-2026-0001",
								"package":"openssl",
								"version":"1.0.1",
								"fix_version":"1.0.2",
								"severity":"Critical",
								"description":"remote code execution"
							}
						]
					}
				}`,
			},
		},
	}, &out)

	response := proxy.HttpResponse{Body: `[{"project_id":1,"name":"library"}]`}
	if err := scanner.ProcessProjects(response, registryURL); err != nil {
		t.Fatalf("ProcessProjects() error = %v", err)
	}

	rows := readCSVRows(t, out.String())
	if len(rows) != 2 {
		t.Fatalf("row count = %d, want 2: %#v", len(rows), rows)
	}
	if rows[0][2] != "team/app" {
		t.Fatalf("repository field = %q, want team/app", rows[0][2])
	}
	if rows[0][5] != "HIGH" {
		t.Fatalf("impact field = %q, want HIGH", rows[0][5])
	}
	if rows[1][5] != "CRITICAL" {
		t.Fatalf("vulnerability severity field = %q, want CRITICAL", rows[1][5])
	}
	if rows[1][7] != "CVE-2026-0001" {
		t.Fatalf("vulnerability signal field = %q, want CVE-2026-0001", rows[1][7])
	}
}

func TestProcessArtifactsContinuesWhenBuildHistoryIsUnsupported(t *testing.T) {
	var out bytes.Buffer
	registryURL := resource.Parse("https://harbor.example.com", "/api/v2.0/projects")
	repositoriesURL := resource.Parse(registryURL.Full, "/library/repositories")

	scanner := New(fakeHTTPClient{
		responses: map[string]fakeResponse{
			"https://harbor.example.com/api/v2.0/projects/library/repositories/app/artifacts": {
				status: http.StatusOK,
				body:   `[{"digest":"sha256:first","tags":[{"name":"v1"}]},{"digest":"sha256:second","tags":[{"name":"v2"}]}]`,
			},
			"https://harbor.example.com/api/v2.0/projects/library/repositories/app/artifacts/sha256:first/additions/build_history": {
				status: http.StatusOK,
				body:   BuildHistoryNotSupported,
			},
			"https://harbor.example.com/api/v2.0/projects/library/repositories/app/artifacts/sha256:first/additions/vulnerabilities": {
				status: http.StatusOK,
				body:   `{}`,
			},
			"https://harbor.example.com/api/v2.0/projects/library/repositories/app/artifacts/sha256:second/additions/build_history": {
				status: http.StatusOK,
				body:   `[{"created_by":"ENV SECRET=value"}]`,
			},
			"https://harbor.example.com/api/v2.0/projects/library/repositories/app/artifacts/sha256:second/additions/vulnerabilities": {
				status: http.StatusOK,
				body:   `{}`,
			},
		},
	}, &out)

	response := proxy.HttpResponse{Body: `[{"name":"library/app"}]`}
	if err := scanner.ProcessArtifacts(response, repositoriesURL, registryURL, entities.Project{Name: "library"}); err != nil {
		t.Fatalf("ProcessArtifacts() error = %v", err)
	}

	rows := readCSVRows(t, out.String())
	if len(rows) != 1 {
		t.Fatalf("row count = %d, want 1: %#v", len(rows), rows)
	}
	if rows[0][3] != "sha256:second" {
		t.Fatalf("digest field = %q, want sha256:second", rows[0][3])
	}
}

func TestProcessArtifactsUsesBoundedRepositoryConcurrency(t *testing.T) {
	var out bytes.Buffer
	registryURL := resource.Parse("https://harbor.example.com", "/api/v2.0/projects")
	repositoriesURL := resource.Parse(registryURL.Full, "/library/repositories")
	client := &trackingHTTPClient{
		delay: 25 * time.Millisecond,
		responses: map[string]fakeResponse{
			"https://harbor.example.com/api/v2.0/projects/library/repositories/app-a/artifacts": {
				status: http.StatusOK,
				body:   `[]`,
			},
			"https://harbor.example.com/api/v2.0/projects/library/repositories/app-b/artifacts": {
				status: http.StatusOK,
				body:   `[]`,
			},
			"https://harbor.example.com/api/v2.0/projects/library/repositories/app-c/artifacts": {
				status: http.StatusOK,
				body:   `[]`,
			},
		},
	}
	scanner := NewWithConfig(client, &out, Config{
		MinVulnerabilitySeverity: LowImpact,
		ScanVulnerabilities:      false,
		MaxConcurrency:           2,
	})

	response := proxy.HttpResponse{Body: `[{"name":"library/app-a"},{"name":"library/app-b"},{"name":"library/app-c"}]`}
	if err := scanner.ProcessArtifacts(response, repositoriesURL, registryURL, entities.Project{Name: "library"}); err != nil {
		t.Fatalf("ProcessArtifacts() error = %v", err)
	}

	if client.MaxActive() > 2 {
		t.Fatalf("max concurrent requests = %d, want <= 2", client.MaxActive())
	}
	if client.MaxActive() < 2 {
		t.Fatalf("max concurrent requests = %d, want worker overlap", client.MaxActive())
	}
}

func TestProcessVulnerabilitiesFiltersBySeverityAndWritesCVERows(t *testing.T) {
	var out bytes.Buffer
	scanner := NewWithConfig(nil, &out, Config{
		MinVulnerabilitySeverity: HighImpact,
		ScanVulnerabilities:      true,
	})
	registryURL := resource.Parse("https://harbor.example.com", "/api/v2.0/projects")
	vulnerabilityURL := resource.Parse("https://harbor.example.com/api/v2.0/projects/library/repositories/app/artifacts/sha256:abc", "/additions/vulnerabilities")
	response := proxy.HttpResponse{Body: `{
		"application/vnd.security.vulnerability.report; version=1.1": {
			"scanner": {"name":"Trivy"},
			"vulnerabilities": [
				{
					"id":"CVE-LOW",
					"package":"busybox",
					"version":"1.0.0",
					"severity":"Low",
					"description":"low severity issue"
				},
				{
					"id":"CVE-HIGH",
					"package":"openssl",
					"version":"1.0.1",
					"fix_version":"1.0.2",
					"severity":"High",
					"cvss_score":8.1,
					"description":"high severity issue with a fix"
				}
			]
		}
	}`}

	err := scanner.ProcessVulnerabilities(
		response,
		vulnerabilityURL,
		registryURL,
		entities.Project{Name: "library"},
		entities.Repository{Name: "library/app"},
		entities.Artifact{Digest: "sha256:abc"},
		[]string{"latest"},
	)
	if err != nil {
		t.Fatalf("ProcessVulnerabilities() error = %v", err)
	}

	rows := readCSVRows(t, out.String())
	if len(rows) != 1 {
		t.Fatalf("row count = %d, want 1: %#v", len(rows), rows)
	}
	row := rows[0]
	if row[5] != "HIGH" {
		t.Fatalf("severity field = %q, want HIGH", row[5])
	}
	if row[7] != "CVE-HIGH" {
		t.Fatalf("signal field = %q, want CVE-HIGH", row[7])
	}
	if !strings.Contains(row[6], "package=openssl") || !strings.Contains(row[6], "fixed=1.0.2") || !strings.Contains(row[6], "scanner=Trivy") {
		t.Fatalf("finding field = %q, want package, fix, and scanner details", row[6])
	}
}

func readCSVRows(t *testing.T, body string) [][]string {
	t.Helper()

	rows, err := csv.NewReader(strings.NewReader(body)).ReadAll()
	if err != nil {
		t.Fatalf("read CSV rows: %v\nbody:\n%s", err, body)
	}
	return rows
}
