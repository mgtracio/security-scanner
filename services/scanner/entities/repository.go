package entities

import (
	"encoding/json"
	"time"
)

type Repository struct {
	ArtifactCount int       `json:"artifact_count"`
	CreationTime  time.Time `json:"creation_time"`
	ID            int       `json:"id"`
	Name          string    `json:"name"`
	ProjectID     int       `json:"project_id"`
	PullCount     int       `json:"pull_count"`
	UpdateTime    time.Time `json:"update_time"`
}

type Repositories []Repository

func ToRepositories(bodyRequest string) (repositories *Repositories, err error) {
	err = json.Unmarshal([]byte(bodyRequest), &repositories)
	return
}