package services

import (
	"fmt"
	proxy "github.com/mgtracio/security-scanner/services/http"
	"github.com/mgtracio/security-scanner/services/scanner/entities"
	resource "github.com/mgtracio/security-scanner/services/url"
	url "github.com/mgtracio/security-scanner/services/url"
	"github.com/mgtracio/security-scanner/utils"
	"io"
	"log"
	goPath "path"
	"strings"
)

type Impact string
const SafeTruncatedLen = 27
const BuildHistoryNotSupported = "BUILD_HISTORY isn't supported"
const CsvRowFormat = "%s,%s,%s,%s,%s,%s,%s,%s,%s\n"
const (
	SECRET      utils.Key = "SECRET"
	TOKEN       utils.Key = "TOKEN"
	PASSWORD    utils.Key = "PASSWORD"
	PSWD     	utils.Key = "PSWD"
	KEY     	utils.Key = "KEY"
	KEYCLOAK    utils.Key = "KEYCLOAK"
	AWS     	utils.Key = "AWS"
	HOST     	utils.Key = "HOST"
	ACCESS     	utils.Key = "ACCESS"
	ARG_ENV     utils.Key = "ARG EN"
	ENV      	utils.Key = "ENV "
)
const (
	MildImpact   Impact = "MILD️"
	HighImpact   Impact = "HIGH"
)
var ArgEnv = []utils.Key{ARG_ENV, ENV}
var SensitiveKeys= []utils.Key{SECRET, TOKEN, PASSWORD, PSWD, KEY}
var PossibleSensitiveKeys= []utils.Key{AWS, HOST, ACCESS, KEYCLOAK}
var AllKeys = append(SensitiveKeys, PossibleSensitiveKeys...)

func ScanEndpoint(resource url.Url) (response proxy.HttpResponse) {
	var message string
	res, err := proxy.Request(resource.Full)
	if err != nil {
		log.Fatalln(err)
	}
	if res.StatusCode == 404 {
		message = "Not found. ❌"
	} else {
		message = "Found. ✅"
	}
	defer res.Body.Close()
	b, err := io.ReadAll(res.Body)
	if err != nil {
		log.Fatalln(err)
	}
	response = proxy.HttpResponse{
		StatusCode: res.StatusCode,
		Path:       resource.Path,
		Message:    message,
		Body: 		string(b),
	}
	return response
}

func ProcessProjects(response proxy.HttpResponse, registryUrl resource.Url) {
	projects, err := entities.ToProjects(response.Body)
	if err != nil {
		log.Fatalln(err)
	}
	for _, project := range *projects {
		urlRepositories := resource.Parse(registryUrl.Full, fmt.Sprintf("/%s/repositories", project.Name))
		response := ScanEndpoint(urlRepositories)
		ProcessArtifacts(response, urlRepositories, registryUrl, project)
	}
}

func ProcessBuild(response proxy.HttpResponse, urlBuildHistory resource.Url, registryUrl resource.Url, project entities.Project, repository entities.Repository, artifact entities.Artifact, tags []string) {
	buildHistory, err := entities.ToABuildHistory(response.Body)
	if err != nil {
		log.Fatalln(urlBuildHistory.Full, err.Error())
	}
	for _, build := range *buildHistory {
		if b, v := utils.Contains(strings.ToUpper(build.CreatedBy), AllKeys); b {
			safeTruncated := build.CreatedBy
			if len(build.CreatedBy) >= SafeTruncatedLen {
				safeTruncated = utils.SafeTruncated(build.CreatedBy, v, safeTruncated)
			}
			var impact = MildImpact
			if sensitve, _ := utils.Contains(strings.ToUpper(build.CreatedBy), SensitiveKeys); sensitve {
				if args, _ := utils.Contains(strings.ToUpper(build.CreatedBy), ArgEnv); args {
					if possibleSensitive, _ := utils.Contains(strings.ToUpper(safeTruncated), PossibleSensitiveKeys); !possibleSensitive {
						impact = HighImpact
					}
				}
			}
			fmt.Printf(CsvRowFormat, registryUrl.Base, project.Name, goPath.Base(repository.Name), artifact.Digest, fmt.Sprintf("\"%s\"", strings.Join(tags, ",")), impact, safeTruncated, v, urlBuildHistory.Full)
		}
	}
}

func ProcessArtifacts(response proxy.HttpResponse, urlRepositories resource.Url, registryUrl resource.Url, project entities.Project) {
	repositories, err := entities.ToRepositories(response.Body)
	if err != nil {
		log.Fatalln(err)
	}
	for _, repository := range *repositories {
		urlArtifacts := resource.Parse(urlRepositories.Full, fmt.Sprintf("/%s/artifacts", goPath.Base(repository.Name)))
		response := ScanEndpoint(urlArtifacts)
		artifacts, err := entities.ToArtifacts(response.Body)
		if err != nil {
			log.Fatalln(err)
		}
		for _, artifact := range *artifacts {
			var tags []string
			for _, tag := range artifact.Tags {
				tags = append(tags, tag.Name)
			}
			urlBuildHistory := resource.Parse(urlArtifacts.Full, fmt.Sprintf("/%s/additions/build_history", artifact.Digest))
			response := ScanEndpoint(urlBuildHistory)
			if strings.Contains(response.Body, BuildHistoryNotSupported) {
				break
			}
			ProcessBuild(response, urlBuildHistory, registryUrl, project, repository, artifact, tags)
		}
	}
}