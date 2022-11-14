package main

import (
	"fmt"
	rules "github.com/mgtracio/security-scanner/services/rules"
	scanner "github.com/mgtracio/security-scanner/services/scanner"
	resource "github.com/mgtracio/security-scanner/services/url"
	"log"
)

func main() {
	const APPNAME string = "Scanner"
	var baseUrl string
	fmt.Printf("%s - Harbor application scanner.\n", APPNAME)
	fmt.Print("Enter the Harbor base url: ")
	fmt.Scan(&baseUrl)
	fmt.Printf("Harbor registry,Project,Repository,Digest,Tags,Impact,Finding,Key found,Harbor API\n")
	apis, err := rules.SetEntries(rules.APIEntriesPath)
	if err != nil {
		log.Fatalln(err)
	}
	for _, path := range apis {
		registryUrl := resource.Parse(baseUrl, path)
		response := scanner.ScanEndpoint(registryUrl)
		scanner.ProcessProjects(response, registryUrl)
	}
	fmt.Printf("Scanning Complete.\n")
}



