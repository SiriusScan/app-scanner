package main

import (
	"fmt"
	"log"

	"github.com/SiriusScan/app-scanner/modules/nmap"
	"github.com/SiriusScan/go-api/sirius"
	"github.com/SiriusScan/go-api/sirius/host"
	_ "github.com/SiriusScan/go-api/sirius/postgres"
	"github.com/SiriusScan/go-api/sirius/postgres/models"
	"github.com/SiriusScan/go-api/sirius/vulnerability"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func main() {
	fmt.Println("Sirius Development Test Suite")

	// * Tests =========



	// testUpdateHost(target)
	// testGetHost()
	// testNmap()
	// dbMigrate()


}

func testTemplate() {
	fmt.Println("Beginning test")

	// Live Test: core.update

	// * Pre-Tests =====

	// * Before =========
	// fmt.Println(target)

	// * Tests =========
	// testUpdateHost(target)
	// testGetHost()
	// testNmap()
	// dbMigrate()

	// * After ==========
	// target = testGetHost("192.168.86.32")
	// fmt.Println(target)
}

func testGetVulnerability(id string) sirius.Entry {
	vuln, err := vulnerability.GetVulnerability(id)
	if err != nil {
		log.Fatalf("Error getting vulnerability: %v", err)
	}

	return vuln
}

func testNmap() {
	nmap.Scan("192.168.86.33")
}

func testGetHost(ip string) sirius.Host {
	var target sirius.Host
	target, err := host.GetHost(ip)
	if err != nil {
		fmt.Println(err)
	}
	return target
}

func testUpdateHost(target sirius.Host) {
	err := host.UpdateHost(target)
	if err != nil {
		fmt.Println(err)
	}
}

func dbMigrate() {

	dsn := "host=localhost user=postgres password=password dbname=sirius port=5432 sslmode=disable"
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})

	if err != nil {
		log.Fatalf("Error connecting to database: %v", err)
	}

	// Auto-migrate the schema
	err = db.AutoMigrate(
		&models.Host{},
		&models.Port{},
		&models.Service{},
		&models.Vulnerability{},
		&models.HostVulnerability{},
		&models.Agent{},
		&models.User{},
		&models.Note{},
		&models.CPE{},
	)

	if err != nil {
		log.Fatalf("Error migrating database schema: %v", err)
	}

	fmt.Println("Database migration complete!")
}

// Test suite => pull new host
// -> goal -> host & cve db with gorm

// Much like host tests
// * Pre-Tests =====

// Vulnerability

// dummyEntry := sirius.Entry{
// 	EntryId:             "6414e68d0737de2aaace17ed",
// 	CVE:                 "CVE-2023-0001",
// 	CVEDataFormat:       "MITRE",
// 	CVEDataType:         "CVE",
// 	CVEDataVersion:      "4.0",
// 	CVEDataNumberOfCVEs: "1",
// 	CVEDataTimestamp:    "2023-09-30T12:34:56Z",
// 	CVEItems:            []sirius.CVEItem{{ /*... fill in as needed ...*/ }},
// 	CVEDataMeta:         sirius.CVEDataMeta{ID: "CVE-2023-0001", ASSIGNER: "psirt@paloaltonetworks.com"},
// 	CPE:                 sirius.Node{Operator: "AND", Children: []sirius.Node{{Operator: "OR", CPEMatch: []sirius.CPEMatch{{CPE23URI: "cpe:2.3:a:paloaltonetworks:cortex_xdr_agent:*:*:*:*:critical_environment:*:*:*", Vulnerable: true}}}}},
// 	CVSSV3:              sirius.CVSSV3{VectorString: "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", BaseScore: 6.7},
// 	References:          []string{"https://security.paloaltonetworks.com/CVE-2023-0001"},
// 	Tags:                []string{"vulnerability", "exposure"},
// }

// // HOST
// target := testGetHost("192.168.86.32")
// //target.Ports = []sirius.Port{{ID: 2223, State: "open"}}
// target.OS = "Linux"
// target.CVE = []string{"CVE-2021-1234", "CVE-2021-5678"}

// * Before =========
// fmt.Println(target)

// * Tests =========
// Call the AddVulnerability function
// if err := vulnerability.AddVulnerability(dummyEntry); err != nil {
// 	// Handle error
// 	println("Failed to add vulnerability:", err.Error())
// } else {
// 	println("Successfully added vulnerability!")
// }

// vuln := testGetVulnerability("CVE-2023-0001")
// fmt.Println(vuln)

// * After ==========
// target = testGetHost("192.168.86.32")
// fmt.Println(target)
