package rustscan

import (
	"bufio"
	"fmt"
	"log"
	"os/exec"
	"strconv"
	"strings"

	"github.com/SiriusScan/go-api/sirius"
)

func Scan(target string) (sirius.Host, error) {
	log.Printf("Starting Rust Scan %s", target)

	cmd := exec.Command("rustscan", "-a", target, "--ulimit", "5000", "--scan-order", "serial", "--top", "-g")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return sirius.Host{}, fmt.Errorf("Failed to get stdout pipe: %v", err)
	}

	if err := cmd.Start(); err != nil {
		return sirius.Host{}, fmt.Errorf("Failed to start command: %v", err)
	}

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "->") {
			hostInfo := parseHostInfo(line)
			return hostInfo, nil
		}
	}

	if err := cmd.Wait(); err != nil {
		return sirius.Host{}, fmt.Errorf("Command execution failed: %v", err)
	}

	return sirius.Host{}, fmt.Errorf("Host not online")
}

func parseHostInfo(line string) sirius.Host {
	log.Printf("Parsing host info: %s", line)
	parts := strings.Split(line, " -> ")
	ip := parts[0]
	portStrs := strings.Trim(parts[1], "[]")
	ports := strings.Split(portStrs, ",")

	var siriusPorts []sirius.Port
	for _, p := range ports {
		port, err := strconv.Atoi(p)
		if err == nil {
			siriusPort := sirius.Port{
				ID: port,
				// Since we don't have Protocol and State info here, you might want to set some defaults or leave them empty
				Protocol: "",
				State:    "",
			}
			siriusPorts = append(siriusPorts, siriusPort)
		}
	}

	return sirius.Host{IP: ip, Ports: siriusPorts}
}
