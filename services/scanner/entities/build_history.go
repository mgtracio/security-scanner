package entities

import (
	"encoding/json"
	"time"
)

type BuildHistory struct {
	Created    time.Time `json:"created"`
	CreatedBy  string    `json:"created_by"`
	EmptyLayer bool      `json:"empty_layer,omitempty"`
	Comment    string    `json:"comment,omitempty"`
}

type BuildHistoryList []BuildHistory

func ToABuildHistory(bodyRequest string) (buildHistory *BuildHistoryList, err error) {
	err = json.Unmarshal([]byte(bodyRequest), &buildHistory)
	return
}
