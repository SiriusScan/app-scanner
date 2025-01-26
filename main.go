package main

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/SiriusScan/go-api/sirius"
	"github.com/SiriusScan/go-api/sirius/host"
	"github.com/SiriusScan/go-api/sirius/queue"

	nmap "github.com/SiriusScan/app-scanner/modules/nmap"
	rustscan "github.com/SiriusScan/app-scanner/modules/rustscan"
)

type ScanMessage struct {
	Message string `json:"message"`
}

func main() {
	fmt.Println("Scanner service is running...")

	// Function to handle messages from the scan queue
	coreExecution := func(msg string) {
		log.Printf("Received message: %s", msg)

		// Unmarshal the JSON string into a ScanMessage struct
		var scanMsg ScanMessage
		err := json.Unmarshal([]byte(msg), &scanMsg)
		if err != nil {
			log.Printf("Failed to unmarshal message: %s", err)
			return
		}

		// Now scanMsg.Message contains the "message" field from the JSON
		log.Printf("Initiating new scan! Targets: %s", scanMsg.Message)

		// Convert string to array
		targetList := strings.Split(scanMsg.Message, ",")

		// Iterate over array
		for _, target := range targetList {
			go func(t string) {
				ScanHandler(t)
			}(target)
		}
	}

	queue.Listen("scan", coreExecution)
}

func ScanHandler(target string) {
	log.Printf("Scanning target %s", target)
	discoveryResults, err := DiscoveryScan(target)
	if err != nil {
		// Target is not online, return
		return
	}

	// * Target is online, addHost to database & start scan
	// * Add host to database
	err = host.AddHost(discoveryResults)
	if err != nil {
		log.Println(err)
	}

	// * Start scan
	scanResults, err := VulnerabilityScan(discoveryResults)
	if err != nil {
		log.Println(err)
	}

	// * Update host with vuln information
	err = host.AddHost(scanResults)
	if err != nil {
		log.Println(err)
	}
	log.Println("Scan complete!")
}

func DiscoveryScan(target string) (sirius.Host, error) {
	log.Printf("Discovering target %s", target)

	// rust scan
	discoveryResults, err := rustscan.Scan(target)
	if err != nil {
		return sirius.Host{}, err
	}

	return discoveryResults, nil
}

func VulnerabilityScan(host sirius.Host) (sirius.Host, error) {
	log.Printf("Performing vulnerability discovery for: %s", host.IP)

	nmapResults, err := nmap.Scan(host.IP)
	if err != nil {
		log.Printf("Error performing Nmap scan: %s", err)
		return sirius.Host{}, err
	}
	return nmapResults, nil
}
