package services

import (
	"encoding/csv"
	"fmt"
	proxy "github.com/mgtracio/security-scanner/services/http"
	"github.com/mgtracio/security-scanner/services/scanner/entities"
	resource "github.com/mgtracio/security-scanner/services/url"
	"io"
	"log"
	"net/http"
	neturl "net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

type Impact string

const BuildHistoryNotSupported = "BUILD_HISTORY isn't supported"
const MaxFindingLen = 320
const DefaultMaxConcurrency = 4

var CSVHeader = []string{"Harbor registry", "Project", "Repository", "Digest", "Tags", "Severity", "Finding", "Signal", "Harbor API"}

const (
	UnknownImpact    Impact = "UNKNOWN"
	NegligibleImpact Impact = "NEGLIGIBLE"
	LowImpact        Impact = "LOW"
	MediumImpact     Impact = "MEDIUM"
	MildImpact       Impact = "MILD"
	HighImpact       Impact = "HIGH"
	CriticalImpact   Impact = "CRITICAL"
)

var sensitiveAssignmentPattern = regexp.MustCompile(`(?i)\b([A-Z0-9_-]*(?:SECRET|TOKEN|PASSWORD|PASSWD|PSWD|PRIVATE[_-]?KEY|ACCESS[_-]?KEY|API[_-]?KEY|AUTH[_-]?TOKEN|CREDENTIAL|CLIENT[_-]?SECRET|SESSION[_-]?KEY)[A-Z0-9_-]*)\b\s*[:=]\s*("[^"]*"|'[^']*'|[^\s]+)`)
var sensitiveDeclarationPattern = regexp.MustCompile(`(?i)\b(?:ARG|ENV|export|--build-arg)\s+([A-Z0-9_-]*(?:SECRET|TOKEN|PASSWORD|PASSWD|PSWD|PRIVATE[_-]?KEY|ACCESS[_-]?KEY|API[_-]?KEY|AUTH[_-]?TOKEN|CREDENTIAL|CLIENT[_-]?SECRET|SESSION[_-]?KEY)[A-Z0-9_-]*)\b`)
var basicAuthURLPattern = regexp.MustCompile(`(?i)\bhttps?://[^/\s:@]+:[^@\s]+@[^/\s]+`)
var privateKeyMarkerPattern = regexp.MustCompile(`(?i)-----BEGIN [A-Z ]*PRIVATE KEY-----`)

type HTTPClient interface {
	Request(url string) (*http.Response, error)
}

type Scanner struct {
	client   HTTPClient
	out      io.Writer
	config   Config
	outputMu sync.Mutex
}

type Config struct {
	MinVulnerabilitySeverity Impact
	ScanVulnerabilities      bool
	MaxConcurrency           int
}

func DefaultConfig() Config {
	return Config{
		MinVulnerabilitySeverity: LowImpact,
		ScanVulnerabilities:      true,
		MaxConcurrency:           DefaultMaxConcurrency,
	}
}

func ParseSeverityThreshold(severity string) (Impact, error) {
	switch strings.ToUpper(strings.TrimSpace(severity)) {
	case "UNKNOWN", "NONE", "":
		return UnknownImpact, nil
	case "NEGLIGIBLE":
		return NegligibleImpact, nil
	case "LOW":
		return LowImpact, nil
	case "MEDIUM", "MODERATE":
		return MediumImpact, nil
	case "HIGH":
		return HighImpact, nil
	case "CRITICAL":
		return CriticalImpact, nil
	default:
		return "", fmt.Errorf("unsupported vulnerability severity %q; use one of: unknown, negligible, low, medium, high, critical", severity)
	}
}

func New(client HTTPClient, out io.Writer) *Scanner {
	return NewWithConfig(client, out, DefaultConfig())
}

func NewWithConfig(client HTTPClient, out io.Writer, config Config) *Scanner {
	if client == nil {
		client = proxy.DefaultClient
	}
	if out == nil {
		out = io.Discard
	}
	if config == (Config{}) {
		config = DefaultConfig()
	}
	if config.MinVulnerabilitySeverity == "" {
		config.MinVulnerabilitySeverity = LowImpact
	}
	if config.MaxConcurrency <= 0 {
		config.MaxConcurrency = DefaultMaxConcurrency
	}

	return &Scanner{
		client: client,
		out:    out,
		config: config,
	}
}

func WriteCSVHeader(out io.Writer) error {
	return writeCSVRow(out, CSVHeader)
}

func ScanEndpoint(registryURL resource.Url) (response proxy.HttpResponse) {
	response, err := New(proxy.DefaultClient, os.Stdout).ScanEndpoint(registryURL)
	if err != nil {
		log.Fatalln(err)
	}
	return response
}

func (s *Scanner) ScanEndpoint(registryURL resource.Url) (proxy.HttpResponse, error) {
	res, err := s.client.Request(registryURL.Full)
	if err != nil {
		return proxy.HttpResponse{}, fmt.Errorf("request %s: %w", registryURL.Full, err)
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return proxy.HttpResponse{}, fmt.Errorf("read response body from %s: %w", registryURL.Full, err)
	}

	response := proxy.HttpResponse{
		StatusCode: res.StatusCode,
		Path:       registryURL.Path,
		Message:    statusMessage(res.StatusCode),
		Body:       string(body),
	}

	if res.StatusCode < http.StatusOK || res.StatusCode >= http.StatusMultipleChoices {
		return response, fmt.Errorf("GET %s returned HTTP %d", registryURL.Full, res.StatusCode)
	}
	return response, nil
}

func ProcessProjects(response proxy.HttpResponse, registryUrl resource.Url) {
	if err := New(proxy.DefaultClient, os.Stdout).ProcessProjects(response, registryUrl); err != nil {
		log.Fatalln(err)
	}
}

func (s *Scanner) ProcessProjects(response proxy.HttpResponse, registryUrl resource.Url) error {
	projects, err := entities.ToProjects(response.Body)
	if err != nil {
		return fmt.Errorf("parse projects response from %s: %w", registryUrl.Full, err)
	}
	for _, project := range *projects {
		urlRepositories := resource.Parse(registryUrl.Full, fmt.Sprintf("/%s/repositories", project.Name))
		response, err := s.ScanEndpoint(urlRepositories)
		if err != nil {
			return err
		}
		if err := s.ProcessArtifacts(response, urlRepositories, registryUrl, project); err != nil {
			return err
		}
	}
	return nil
}

func ProcessBuild(response proxy.HttpResponse, urlBuildHistory resource.Url, registryUrl resource.Url, project entities.Project, repository entities.Repository, artifact entities.Artifact, tags []string) {
	if err := New(proxy.DefaultClient, os.Stdout).ProcessBuild(response, urlBuildHistory, registryUrl, project, repository, artifact, tags); err != nil {
		log.Fatalln(err)
	}
}

func (s *Scanner) ProcessBuild(response proxy.HttpResponse, urlBuildHistory resource.Url, registryUrl resource.Url, project entities.Project, repository entities.Repository, artifact entities.Artifact, tags []string) error {
	buildHistory, err := entities.ToABuildHistory(response.Body)
	if err != nil {
		return fmt.Errorf("parse build history response from %s: %w", urlBuildHistory.Full, err)
	}
	for _, build := range *buildHistory {
		for _, finding := range buildHistoryFindings(build.CreatedBy) {
			if err := s.writeCSVRow([]string{
				registryUrl.Base,
				project.Name,
				repositoryName(project.Name, repository.Name),
				artifact.Digest,
				strings.Join(tags, ","),
				string(finding.impact),
				finding.finding,
				finding.signal,
				urlBuildHistory.Full,
			}); err != nil {
				return err
			}
		}
	}
	return nil
}

func ProcessArtifacts(response proxy.HttpResponse, urlRepositories resource.Url, registryUrl resource.Url, project entities.Project) {
	if err := New(proxy.DefaultClient, os.Stdout).ProcessArtifacts(response, urlRepositories, registryUrl, project); err != nil {
		log.Fatalln(err)
	}
}

func (s *Scanner) ProcessArtifacts(response proxy.HttpResponse, urlRepositories resource.Url, registryUrl resource.Url, project entities.Project) error {
	repositories, err := entities.ToRepositories(response.Body)
	if err != nil {
		return fmt.Errorf("parse repositories response from %s: %w", urlRepositories.Full, err)
	}
	return s.forEachRepository(*repositories, func(repository entities.Repository) error {
		return s.processRepository(urlRepositories, registryUrl, project, repository)
	})
}

func (s *Scanner) processRepository(urlRepositories resource.Url, registryUrl resource.Url, project entities.Project, repository entities.Repository) error {
	urlArtifacts := resource.Parse(urlRepositories.Full, fmt.Sprintf("/%s/artifacts", repositoryPathSegment(project.Name, repository.Name)))
	response, err := s.ScanEndpoint(urlArtifacts)
	if err != nil {
		return err
	}
	artifacts, err := entities.ToArtifacts(response.Body)
	if err != nil {
		return fmt.Errorf("parse artifacts response from %s: %w", urlArtifacts.Full, err)
	}
	for _, artifact := range *artifacts {
		if err := s.processArtifact(urlArtifacts, registryUrl, project, repository, artifact); err != nil {
			return err
		}
	}
	return nil
}

func (s *Scanner) processArtifact(urlArtifacts resource.Url, registryUrl resource.Url, project entities.Project, repository entities.Repository, artifact entities.Artifact) error {
	var tags []string
	for _, tag := range artifact.Tags {
		tags = append(tags, tag.Name)
	}

	urlBuildHistory := artifactAdditionURL(
		registryUrl,
		urlArtifacts,
		artifact.AdditionLinks.BuildHistory.Href,
		fmt.Sprintf("/%s/additions/build_history", artifactReference(artifact.Digest)),
	)
	response, err := s.ScanEndpoint(urlBuildHistory)
	if err != nil {
		if !isAdditionUnavailable(response) {
			return err
		}
	} else if !strings.Contains(response.Body, BuildHistoryNotSupported) {
		if err := s.ProcessBuild(response, urlBuildHistory, registryUrl, project, repository, artifact, tags); err != nil {
			return err
		}
	}

	if !s.config.ScanVulnerabilities {
		return nil
	}

	urlVulnerabilities := artifactAdditionURL(
		registryUrl,
		urlArtifacts,
		artifact.AdditionLinks.Vulnerabilities.Href,
		fmt.Sprintf("/%s/additions/vulnerabilities", artifactReference(artifact.Digest)),
	)
	response, err = s.ScanEndpoint(urlVulnerabilities)
	if err != nil {
		if !isAdditionUnavailable(response) {
			return err
		}
		return nil
	}
	return s.ProcessVulnerabilities(response, urlVulnerabilities, registryUrl, project, repository, artifact, tags)
}

func (s *Scanner) ProcessVulnerabilities(response proxy.HttpResponse, urlVulnerabilities resource.Url, registryUrl resource.Url, project entities.Project, repository entities.Repository, artifact entities.Artifact, tags []string) error {
	reports, err := entities.ToVulnerabilityReports(response.Body)
	if err != nil {
		return fmt.Errorf("parse vulnerability response from %s: %w", urlVulnerabilities.Full, err)
	}

	for _, report := range *reports {
		for _, vulnerability := range report.Vulnerabilities {
			severity := vulnerabilitySeverity(vulnerability, report)
			if !meetsSeverityThreshold(severity, s.config.MinVulnerabilitySeverity) {
				continue
			}

			signal := vulnerability.ID
			if signal == "" {
				signal = vulnerability.Package
			}

			if err := s.writeCSVRow([]string{
				registryUrl.Base,
				project.Name,
				repositoryName(project.Name, repository.Name),
				artifact.Digest,
				strings.Join(tags, ","),
				string(severity),
				vulnerabilityFinding(report, vulnerability),
				signal,
				urlVulnerabilities.Full,
			}); err != nil {
				return err
			}
		}
	}
	return nil
}

type buildHistoryFinding struct {
	impact  Impact
	finding string
	signal  string
}

func buildHistoryFindings(createdBy string) []buildHistoryFinding {
	var findings []buildHistoryFinding
	seen := map[string]struct{}{}

	if privateKeyMarkerPattern.MatchString(createdBy) {
		findings = append(findings, buildHistoryFinding{
			impact:  CriticalImpact,
			finding: "SECRET_MATERIAL private_key=<redacted>",
			signal:  "PRIVATE_KEY",
		})
		seen["PRIVATE_KEY"] = struct{}{}
	}

	for _, match := range sensitiveAssignmentPattern.FindAllStringSubmatch(createdBy, -1) {
		if len(match) < 3 {
			continue
		}
		name := normalizeSignal(match[1])
		if _, ok := seen["assignment:"+name]; ok {
			continue
		}
		seen["assignment:"+name] = struct{}{}
		seen[name] = struct{}{}

		impact := HighImpact
		if isSecretReference(match[2]) {
			impact = MediumImpact
		}
		if strings.Contains(name, "PRIVATE_KEY") {
			impact = CriticalImpact
		}

		findings = append(findings, buildHistoryFinding{
			impact:  impact,
			finding: "SECRET_ASSIGNMENT " + name + "=<redacted>",
			signal:  name,
		})
	}

	for _, match := range sensitiveDeclarationPattern.FindAllStringSubmatch(createdBy, -1) {
		if len(match) < 2 {
			continue
		}
		name := normalizeSignal(match[1])
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}

		findings = append(findings, buildHistoryFinding{
			impact:  MediumImpact,
			finding: "SECRET_REFERENCE " + name,
			signal:  name,
		})
	}

	if basicAuthURLPattern.MatchString(createdBy) {
		findings = append(findings, buildHistoryFinding{
			impact:  HighImpact,
			finding: "SECRET_IN_URL credentials=<redacted>",
			signal:  "BASIC_AUTH_URL",
		})
	}

	return findings
}

func normalizeSignal(signal string) string {
	return strings.ToUpper(strings.Trim(signal, " \t\r\n\"'"))
}

func isSecretReference(value string) bool {
	normalized := strings.Trim(strings.TrimSpace(value), "\"'")
	upper := strings.ToUpper(normalized)
	if normalized == "" {
		return true
	}
	if strings.HasPrefix(normalized, "$") || strings.HasPrefix(normalized, "${") {
		return true
	}
	switch upper {
	case "<REDACTED>", "REDACTED", "***", "****", "XXXXX", "CHANGEME", "CHANGE_ME", "DUMMY", "EXAMPLE", "PLACEHOLDER":
		return true
	default:
		return false
	}
}

func (s *Scanner) forEachRepository(repositories entities.Repositories, process func(entities.Repository) error) error {
	if len(repositories) == 0 {
		return nil
	}
	if s.config.MaxConcurrency <= 1 || len(repositories) == 1 {
		for _, repository := range repositories {
			if err := process(repository); err != nil {
				return err
			}
		}
		return nil
	}

	workers := s.config.MaxConcurrency
	if workers > len(repositories) {
		workers = len(repositories)
	}

	jobs := make(chan entities.Repository)
	var wg sync.WaitGroup
	var errMu sync.Mutex
	var firstErr error

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for repository := range jobs {
				if err := process(repository); err != nil {
					errMu.Lock()
					if firstErr == nil {
						firstErr = err
					}
					errMu.Unlock()
				}
			}
		}()
	}

	for _, repository := range repositories {
		jobs <- repository
	}
	close(jobs)
	wg.Wait()

	return firstErr
}

func repositoryName(projectName string, fullRepositoryName string) string {
	repositoryName := strings.TrimPrefix(fullRepositoryName, projectName+"/")
	if repositoryName == "" {
		return fullRepositoryName
	}
	return repositoryName
}

func repositoryPathSegment(projectName string, fullRepositoryName string) string {
	// Harbor expects slash-containing repository names to be URL encoded in path parameters.
	return neturl.PathEscape(neturl.PathEscape(repositoryName(projectName, fullRepositoryName)))
}

func artifactReference(reference string) string {
	return neturl.PathEscape(reference)
}

func artifactAdditionURL(registryUrl resource.Url, urlArtifacts resource.Url, href string, fallbackPath string) resource.Url {
	href = strings.TrimSpace(href)
	if href == "" {
		return resource.Parse(urlArtifacts.Full, fallbackPath)
	}
	if strings.HasPrefix(href, "http://") || strings.HasPrefix(href, "https://") {
		parsed, err := neturl.Parse(href)
		if err == nil {
			return resource.Url{
				Base: fmt.Sprintf("%s://%s", parsed.Scheme, parsed.Host),
				Path: parsed.RequestURI(),
				Full: href,
			}
		}
	}
	if strings.HasPrefix(href, "/") {
		return resource.Parse(registryUrl.Base, href)
	}
	return resource.Parse(urlArtifacts.Full, href)
}

func isAdditionUnavailable(response proxy.HttpResponse) bool {
	if response.StatusCode == http.StatusNotFound ||
		response.StatusCode == http.StatusPreconditionFailed ||
		response.StatusCode == http.StatusUnsupportedMediaType {
		return true
	}
	return strings.Contains(response.Body, BuildHistoryNotSupported)
}

func vulnerabilitySeverity(vulnerability entities.Vulnerability, report entities.VulnerabilityReport) Impact {
	if vulnerability.Severity != "" {
		return normalizeImpact(vulnerability.Severity)
	}
	return normalizeImpact(report.Severity)
}

func vulnerabilityFinding(report entities.VulnerabilityReport, vulnerability entities.Vulnerability) string {
	parts := []string{"VULNERABILITY"}
	if vulnerability.Package != "" {
		parts = append(parts, "package="+vulnerability.Package)
	}
	if vulnerability.Version != "" {
		parts = append(parts, "installed="+vulnerability.Version)
	}
	if vulnerability.FixVersion != "" {
		parts = append(parts, "fixed="+vulnerability.FixVersion)
	} else {
		parts = append(parts, "fixed=unavailable")
	}
	if vulnerability.CVSSScore > 0 {
		parts = append(parts, "cvss="+strconv.FormatFloat(vulnerability.CVSSScore, 'f', 1, 64))
	}
	if report.Scanner.Name != "" {
		parts = append(parts, "scanner="+report.Scanner.Name)
	}
	if vulnerability.Description != "" {
		parts = append(parts, "description="+limitString(compactWhitespace(vulnerability.Description), MaxFindingLen))
	}
	return strings.Join(parts, " ")
}

func normalizeImpact(severity string) Impact {
	switch strings.ToUpper(strings.TrimSpace(severity)) {
	case "CRITICAL":
		return CriticalImpact
	case "HIGH":
		return HighImpact
	case "MEDIUM", "MODERATE":
		return MediumImpact
	case "LOW":
		return LowImpact
	case "NEGLIGIBLE":
		return NegligibleImpact
	case "NONE", "UNKNOWN", "":
		return UnknownImpact
	default:
		return UnknownImpact
	}
}

func meetsSeverityThreshold(severity Impact, minimum Impact) bool {
	severityValue, severityKnown := impactRank(severity)
	minimumValue, minimumKnown := impactRank(minimum)
	if !severityKnown {
		severityValue = 0
	}
	if !minimumKnown {
		minimumValue = impactRanks[LowImpact]
	}
	return severityValue >= minimumValue
}

var impactRanks = map[Impact]int{
	UnknownImpact:    0,
	NegligibleImpact: 0,
	LowImpact:        1,
	MediumImpact:     2,
	MildImpact:       2,
	HighImpact:       3,
	CriticalImpact:   4,
}

func impactRank(impact Impact) (int, bool) {
	rank, ok := impactRanks[normalizeImpact(string(impact))]
	return rank, ok
}

func compactWhitespace(value string) string {
	return strings.Join(strings.Fields(value), " ")
}

func limitString(value string, limit int) string {
	if limit <= 0 || len(value) <= limit {
		return value
	}
	if limit <= 3 {
		return value[:limit]
	}
	return value[:limit-3] + "..."
}

func statusMessage(statusCode int) string {
	if statusCode == http.StatusNotFound {
		return "Not found"
	}
	if statusCode >= http.StatusOK && statusCode < http.StatusMultipleChoices {
		return "Found"
	}
	if text := http.StatusText(statusCode); text != "" {
		return text
	}
	return "Unexpected status"
}

func writeCSVRow(out io.Writer, record []string) error {
	if out == nil {
		out = io.Discard
	}

	writer := csv.NewWriter(out)
	if err := writer.Write(record); err != nil {
		return err
	}
	writer.Flush()
	return writer.Error()
}

func (s *Scanner) writeCSVRow(record []string) error {
	s.outputMu.Lock()
	defer s.outputMu.Unlock()
	return writeCSVRow(s.out, record)
}
