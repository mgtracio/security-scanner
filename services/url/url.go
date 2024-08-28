package services

import (
	"fmt"
)

type Url struct {
	Base string
	Path string
	Full string
}

func Parse(base string, path string) Url {
	return Url{
		base,
		path,
		fmt.Sprintf("%s%s", base, path),
	}
}