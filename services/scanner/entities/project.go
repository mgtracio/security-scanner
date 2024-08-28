package entities

import (
    "encoding/json"
    "time"
)

type Project struct {
    ProjectID          int         `json:"project_id"`
    OwnerID            int         `json:"owner_id"`
    Name               string      `json:"name"`
    CreationTime       time.Time   `json:"creation_time"`
    UpdateTime         time.Time   `json:"update_time"`
    Deleted            bool        `json:"deleted"`
}

type Projects []Project

func ToProjects(bodyRequest string) (projects *Projects, err error) {
    err = json.Unmarshal([]byte(bodyRequest), &projects)
    return
}