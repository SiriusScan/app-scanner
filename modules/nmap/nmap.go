package nmap

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"os/exec"
	"strings"

	"github.com/SiriusScan/go-api/sirius"
	"github.com/lair-framework/go-nmap"
)

// Scan is a function variable that can be overridden for testing.
var Scan = scanImpl

// scanImpl is the default implementation of the Nmap scan.
func scanImpl(target string) (sirius.Host, error) {
	fmt.Printf("Scanning target %s\n", target)

	// Initialize an empty sirius.Host object
	host := sirius.Host{}

	// Execute Nmap and capture stdout
	output, err := executeNmap(target)
	if err != nil {
		return host, err
	}

	// Process the XML data
	host, err = processNmapOutput(string(output))
	if err != nil {
		return host, err
	}

	return host, nil
}

func executeNmap(target string) (string, error) {
	cmd := exec.Command("nmap", "-T4", "-sV", "-Pn", "--script=vuln,vulners,safe,default,smb-os-discovery", target, "-oX", "-")
	// cmd := exec.Command("nmap", "-T5", "-sV", "-Pn", "--script=vulners", target, "-oX", "-")

	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("Error executing Nmap: %v", err)
	}

	return stdout.String(), nil
}

func processNmapOutput(output string) (sirius.Host, error) {
	fmt.Println("Processing Nmap output")
	host := sirius.Host{}

	var nmapRun nmap.NmapRun
	if err := xml.Unmarshal([]byte(output), &nmapRun); err != nil {
		return host, fmt.Errorf("Error unmarshalling XML: %v", err)
	}

	if len(nmapRun.Hosts) == 0 {
		return host, fmt.Errorf("No hosts found in Nmap XML data")
	}

	nmapHost := nmapRun.Hosts[0]

	if len(nmapHost.Addresses) > 0 {
		var ip string
		for _, address := range nmapHost.Addresses {
			if address.AddrType == "ipv4" || address.AddrType == "ipv6" {
				ip = address.Addr
				break
			}
		}
		host.IP = ip
	}

	if len(nmapHost.Os.OsMatches) > 0 && len(nmapHost.Os.OsMatches[0].OsClasses) > 0 {
		host.OS = nmapHost.Os.OsMatches[0].Name
		host.OSVersion = nmapHost.Os.OsMatches[0].OsClasses[0].OsGen
	}

	// Populate Hostname
	if len(nmapHost.Hostnames) > 0 {
		host.Hostname = nmapHost.Hostnames[0].Name
	}

	// Populate Ports and Services
	var ports []sirius.Port
	var services []sirius.Service
	for _, port := range nmapHost.Ports {
		p := sirius.Port{
			ID:       port.PortId,
			Protocol: port.Protocol,
			State:    port.State.State,
		}
		ports = append(ports, p)
	}
	host.Ports = ports
	host.Services = services

	// Populate CVEs
	cveList := getCVEs(nmapHost)
	for _, cve := range cveList {
		host.Vulnerabilities = append(host.Vulnerabilities, sirius.Vulnerability{Title: cve})
	}

	return host, nil
}

type CVE struct {
	CVEID string `json:"cveid"`
}

func getCVEs(nmapHost nmap.Host) []string {
	cvelist := []string{}

	// Extract CVEs from HostScript Output
	if len(nmapHost.HostScripts) > 0 {
		for _, hostScript := range nmapHost.HostScripts {
			for _, line := range strings.Split(strings.TrimSuffix(hostScript.Output, "\n"), "\n") {
				if strings.Contains(line, "CVE-") {
					cveid := strings.Split(line, "CVE-")[1]
					if len(cveid) > 9 {
						cveid = cveid[:10]
					} else {
						cveid = cveid[:9]
					}
					cvelist = append(cvelist, cveid)
				}
			}
		}
	}

	// Extract CVEs from Port Script Output
	for i := 0; i < len(nmapHost.Ports); i++ {
		for j := 0; j < len(nmapHost.Ports[i].Scripts); j++ {
			scriptOutput := nmapHost.Ports[i].Scripts[j].Output
			for _, line := range strings.Split(strings.TrimSuffix(scriptOutput, "\n"), "\n") {
				if strings.Contains(line, "CVE-") {
					cveid := strings.Split(line, "CVE-")[1]
					if len(cveid) > 9 {
						cveid = cveid[:10]
						cvelist = append(cvelist, cveid)
					} else {
						cveid = cveid[:9]
						cvelist = append(cvelist, cveid)
					}
				}
			}
		}
	}

	return cvelist
}