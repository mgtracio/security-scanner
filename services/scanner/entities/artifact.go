package entities

import (
	"encoding/json"
	"time"
)

type Tag struct {
	ArtifactID   int       `json:"artifact_id"`
	ID           int       `json:"id"`
	Immutable    bool      `json:"immutable"`
	Name         string    `json:"name"`
	PullTime     time.Time `json:"pull_time"`
	PushTime     time.Time `json:"push_time"`
	RepositoryID int       `json:"repository_id"`
	Signed       bool      `json:"signed"`
}
type Artifact struct {
	AdditionLinks struct {
		BuildHistory struct {
			Absolute bool   `json:"absolute"`
			Href     string `json:"href"`
		} `json:"build_history"`
		Vulnerabilities struct {
			Absolute bool   `json:"absolute"`
			Href     string `json:"href"`
		} `json:"vulnerabilities"`
	} `json:"addition_links"`
	Digest     string `json:"digest"`
	Tags       []Tag `json:"tags"`
}

type Artifacts []Artifact

func ToArtifacts(bodyRequest string) (artifacts *Artifacts, err error) {
	err = json.Unmarshal([]byte(bodyRequest), &artifacts)
	return
}