package main

import (
	"fmt"
)

func main() {
	g := newGuardDutyClient()
	detecterIDs, err := g.listDetectors()
	if err != nil {
		panic(err)
	}
	for _, id := range *detecterIDs {
		fmt.Printf("detecterId: %s\n", id)
		findingIDs, err := g.listFindings("315855282677", id) //TODO
		if err != nil {
			panic(err)
		}

		findings, err := g.getFindings(id, findingIDs)
		if err != nil {
			panic(err)
		}
		fmt.Printf("findings: %+v\n", findings)
	}
}
