package main

import (
	"flag"
	"fmt"
	proxy "github.com/mgtracio/security-scanner/services/http"
	rules "github.com/mgtracio/security-scanner/services/rules"
	scanner "github.com/mgtracio/security-scanner/services/scanner"
	resource "github.com/mgtracio/security-scanner/services/url"
	"io"
	"log"
	"os"
	"strings"
)

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		log.Fatalln(err)
	}
}

func run(args []string, in io.Reader, out io.Writer, errOut io.Writer) error {
	const appName = "Scanner"

	flags := flag.NewFlagSet(appName, flag.ContinueOnError)
	flags.SetOutput(errOut)

	baseURL := flags.String("base-url", "", "Harbor base URL, for example https://harbor.example.com")
	entriesPath := flags.String("entries", rules.APIEntriesPath, "path to Harbor API entry list")
	insecureSkipTLSVerify := flags.Bool("insecure-skip-tls-verify", false, "allow insecure TLS certificates when connecting to Harbor")
	timeout := flags.Duration("timeout", proxy.DefaultTimeout, "HTTP request timeout")
	minVulnerabilitySeverity := flags.String("min-vulnerability-severity", string(scanner.LowImpact), "minimum vulnerability severity to emit: unknown, negligible, low, medium, high, critical")
	scanVulnerabilities := flags.Bool("scan-vulnerabilities", true, "scan Harbor artifact vulnerability reports")
	concurrency := flags.Int("concurrency", scanner.DefaultMaxConcurrency, "maximum concurrent Harbor repository scans")

	if err := flags.Parse(args); err != nil {
		return err
	}

	trimmedBaseURL := strings.TrimSpace(*baseURL)
	fmt.Fprintf(errOut, "%s - Harbor application scanner.\n", appName)
	if trimmedBaseURL == "" {
		fmt.Fprint(errOut, "Enter the Harbor base url: ")
		if _, err := fmt.Fscan(in, &trimmedBaseURL); err != nil {
			return fmt.Errorf("read Harbor base URL: %w", err)
		}
		trimmedBaseURL = strings.TrimSpace(trimmedBaseURL)
	}
	if trimmedBaseURL == "" {
		return fmt.Errorf("Harbor base URL is required")
	}

	if *timeout <= 0 {
		return fmt.Errorf("timeout must be positive")
	}
	if *concurrency <= 0 {
		return fmt.Errorf("concurrency must be positive")
	}
	severityThreshold, err := scanner.ParseSeverityThreshold(*minVulnerabilitySeverity)
	if err != nil {
		return err
	}

	apis, err := rules.SetEntries(*entriesPath)
	if err != nil {
		return err
	}
	if len(apis) == 0 {
		return fmt.Errorf("no API entries found in %s", *entriesPath)
	}

	if err := scanner.WriteCSVHeader(out); err != nil {
		return err
	}

	client := proxy.NewClient(proxy.ClientConfig{
		Timeout:               *timeout,
		InsecureSkipTLSVerify: *insecureSkipTLSVerify,
	})
	harborScanner := scanner.NewWithConfig(client, out, scanner.Config{
		MinVulnerabilitySeverity: severityThreshold,
		ScanVulnerabilities:      *scanVulnerabilities,
		MaxConcurrency:           *concurrency,
	})

	for _, path := range apis {
		registryURL := resource.Parse(trimmedBaseURL, path)
		response, err := harborScanner.ScanEndpoint(registryURL)
		if err != nil {
			return err
		}
		if err := harborScanner.ProcessProjects(response, registryURL); err != nil {
			return err
		}
	}
	fmt.Fprintln(errOut, "Scanning complete.")
	return nil
}
