package services

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestClientUsesSecureTLSByDefault(t *testing.T) {
	client := NewClient(ClientConfig{Timeout: time.Second})
	transport := client.httpClient.Transport.(*http.Transport)

	if transport.TLSClientConfig != nil && transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("default client must not skip TLS certificate verification")
	}
}

func TestClientAllowsExplicitInsecureTLSConfig(t *testing.T) {
	client := NewClient(ClientConfig{
		Timeout:               time.Second,
		InsecureSkipTLSVerify: true,
	})
	transport := client.httpClient.Transport.(*http.Transport)

	if transport.TLSClientConfig == nil || !transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("expected explicit insecure client to skip TLS certificate verification")
	}
}

func TestRequestSetsAcceptHeader(t *testing.T) {
	transport := &recordingRoundTripper{}
	client := &Client{
		httpClient: &http.Client{
			Transport: transport,
		},
	}

	res, err := client.Request("https://harbor.example.com/api/v2.0/projects")
	if err != nil {
		t.Fatalf("Request() error = %v", err)
	}
	defer res.Body.Close()

	if got := transport.request.Header.Get("Accept"); got != "application/json" {
		t.Fatalf("Accept header = %q, want application/json", got)
	}
	if got := transport.request.Header.Get("X-Accept-Vulnerabilities"); got != HarborVulnerabilityAcceptHeader {
		t.Fatalf("X-Accept-Vulnerabilities header = %q, want %q", got, HarborVulnerabilityAcceptHeader)
	}
}

type recordingRoundTripper struct {
	request *http.Request
}

func (r *recordingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	r.request = req
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(`{"ok":true}`)),
		Header:     make(http.Header),
	}, nil
}
