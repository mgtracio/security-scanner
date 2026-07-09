package services

import (
	"encoding/csv"
	"fmt"
	proxy "github.com/mgtracio/security-scanner/services/http"
	"github.com/mgtracio/security-scanner/services/scanner/entities"
	resource "github.com/mgtracio/security-scanner/services/url"
	"github.com/mgtracio/security-scanner/utils"
	"io"
	"log"
	"net/http"
	neturl "net/url"
	"os"
	"strconv"
	"strings"
)

type Impact string

const SafeTruncatedLen = 27
const BuildHistoryNotSupported = "BUILD_HISTORY isn't supported"
const MaxFindingLen = 320

var CSVHeader = []string{"Harbor registry", "Project", "Repository", "Digest", "Tags", "Severity", "Finding", "Signal", "Harbor API"}

const (
	SECRET   utils.Key = "SECRET"
	TOKEN    utils.Key = "TOKEN"
	PASSWORD utils.Key = "PASSWORD"
	PSWD     utils.Key = "PSWD"
	KEY      utils.Key = "KEY"
	KEYCLOAK utils.Key = "KEYCLOAK"
	AWS      utils.Key = "AWS"
	HOST     utils.Key = "HOST"
	ACCESS   utils.Key = "ACCESS"
	ARG_ENV  utils.Key = "ARG EN"
	ENV      utils.Key = "ENV "
)
const (
	UnknownImpact    Impact = "UNKNOWN"
	NegligibleImpact Impact = "NEGLIGIBLE"
	LowImpact        Impact = "LOW"
	MediumImpact     Impact = "MEDIUM"
	MildImpact       Impact = "MILD"
	HighImpact       Impact = "HIGH"
	CriticalImpact   Impact = "CRITICAL"
)

var ArgEnv = []utils.Key{ARG_ENV, ENV}
var SensitiveKeys = []utils.Key{SECRET, TOKEN, PASSWORD, PSWD, KEY}
var PossibleSensitiveKeys = []utils.Key{AWS, HOST, ACCESS, KEYCLOAK}
var AllKeys = append(SensitiveKeys, PossibleSensitiveKeys...)

type HTTPClient interface {
	Request(url string) (*http.Response, error)
}

type Scanner struct {
	client HTTPClient
	out    io.Writer
	config Config
}

type Config struct {
	MinVulnerabilitySeverity Impact
	ScanVulnerabilities      bool
}

func DefaultConfig() Config {
	return Config{
		MinVulnerabilitySeverity: LowImpact,
		ScanVulnerabilities:      true,
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
		impact, finding, key, ok := classifyCreatedBy(build.CreatedBy)
		if !ok {
			continue
		}

		if err := writeCSVRow(s.out, []string{
			registryUrl.Base,
			project.Name,
			repositoryName(project.Name, repository.Name),
			artifact.Digest,
			strings.Join(tags, ","),
			string(impact),
			finding,
			key,
			urlBuildHistory.Full,
		}); err != nil {
			return err
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
	for _, repository := range *repositories {
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
				continue
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
				continue
			}
			if err := s.ProcessVulnerabilities(response, urlVulnerabilities, registryUrl, project, repository, artifact, tags); err != nil {
				return err
			}
		}
	}
	return nil
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

			if err := writeCSVRow(s.out, []string{
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

func classifyCreatedBy(createdBy string) (Impact, string, string, bool) {
	upperCreatedBy := strings.ToUpper(createdBy)
	found, key := firstKeyOccurrence(upperCreatedBy, AllKeys)
	if !found {
		return "", "", "", false
	}

	finding := createdBy
	if len(createdBy) >= SafeTruncatedLen {
		finding = utils.SafeTruncated(createdBy, key, finding)
	}

	impact := MildImpact
	if sensitive, _ := utils.Contains(upperCreatedBy, SensitiveKeys); sensitive {
		if hasEnvInstruction, _ := utils.Contains(upperCreatedBy, ArgEnv); hasEnvInstruction {
			if possibleSensitive, _ := utils.Contains(strings.ToUpper(finding), PossibleSensitiveKeys); !possibleSensitive {
				impact = HighImpact
			}
		}
	}

	return impact, finding, key, true
}

func firstKeyOccurrence(value string, keys []utils.Key) (bool, string) {
	bestIndex := -1
	var bestKey string

	for _, key := range keys {
		index := strings.Index(value, string(key))
		if index == -1 {
			continue
		}
		if bestIndex == -1 || index < bestIndex {
			bestIndex = index
			bestKey = string(key)
		}
	}

	return bestIndex >= 0, bestKey
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
