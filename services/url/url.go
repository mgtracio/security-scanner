package services

import (
	"fmt"
	"strings"
)

type Url struct {
	Base string
	Path string
	Full string
}

func Parse(base string, path string) Url {
	normalizedBase := strings.TrimRight(strings.TrimSpace(base), "/")
	normalizedPath := "/" + strings.TrimLeft(strings.TrimSpace(path), "/")

	return Url{
		Base: normalizedBase,
		Path: normalizedPath,
		Full: fmt.Sprintf("%s%s", normalizedBase, normalizedPath),
	}
}
