package services

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"time"
)

const DefaultTimeout = 30 * time.Second
const HarborVulnerabilityAcceptHeader = "application/vnd.security.vulnerability.report; version=1.1, application/vnd.scanner.adapter.vuln.report.harbor+json; version=1.0"

type HttpResponse struct {
	StatusCode int
	Path       string
	Message    string
	Body       string
}

type ClientConfig struct {
	Timeout               time.Duration
	InsecureSkipTLSVerify bool
}

type Client struct {
	httpClient *http.Client
}

var DefaultClient = NewClient(ClientConfig{})

func NewClient(config ClientConfig) *Client {
	timeout := config.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	if config.InsecureSkipTLSVerify {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	return &Client{
		httpClient: &http.Client{
			Timeout:   timeout,
			Transport: transport,
		},
	}
}

func Request(url string) (*http.Response, error) {
	return DefaultClient.Request(url)
}

func (c *Client) Request(url string) (*http.Response, error) {
	if c == nil || c.httpClient == nil {
		return nil, fmt.Errorf("http client is not configured")
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Accept-Vulnerabilities", HarborVulnerabilityAcceptHeader)

	return c.httpClient.Do(req)
}

func LogResponse(res HttpResponse) {
	log.Printf(
		"GET %s: status=%d message=%q body=%s",
		res.Path,
		res.StatusCode,
		res.Message,
		res.Body,
	)
}
