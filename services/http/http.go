package services

import (
	"crypto/tls"
	"log"
	"net/http"
)

type HttpResponse struct {
	StatusCode int
	Path       string
	Message    string
	Body	   string
}

func Request(url string) (*http.Response, error) {
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	res, err := http.Get(url)
	return res, err
}

func LogResponse(res HttpResponse) {
	log.Printf(
		"%d %d: GET %s: Status: %d - %s: Body: %s\n",
		log.Ldate,
		log.Ltime,
		res.Path,
		res.StatusCode,
		res.Message,
		res.Body,
	)
}