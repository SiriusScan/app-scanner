package nse

// ScriptBlacklist contains scripts that should NEVER be executed
// Categories:
// 1. Brute-force scripts - not useful for CVE detection
// 2. DOS/Fuzzing scripts - dangerous and not useful
// 3. Info-gathering scripts - low value for CVE detection
// 4. Scripts with known syntax errors or compatibility issues

var ScriptBlacklist = map[string]string{
	// === BRUTE FORCE SCRIPTS (71 total) - NOT USEFUL FOR CVE DETECTION ===
	"afp-brute":                      "brute",
	"ajp-brute":                      "brute",
	"backorifice-brute":              "brute",
	"cassandra-brute":                "brute",
	"cics-user-brute":                "brute",
	"citrix-brute-xml":               "brute",
	"cvs-brute":                      "brute",
	"cvs-brute-repository":           "brute",
	"deluge-rpc-brute":               "brute",
	"dicom-brute":                    "brute",
	"dns-brute":                      "brute",
	"domcon-brute":                   "brute",
	"dpap-brute":                     "brute",
	"drda-brute":                     "brute",
	"ftp-brute":                      "brute",
	"http-brute":                     "brute",
	"http-form-brute":                "brute",
	"http-iis-short-name-brute":      "brute",
	"http-joomla-brute":              "brute",
	"http-proxy-brute":               "brute",
	"http-wordpress-brute":           "brute",
	"iax2-brute":                     "brute",
	"imap-brute":                     "brute",
	"informix-brute":                 "brute",
	"ipmi-brute":                     "brute",
	"irc-brute":                      "brute",
	"irc-sasl-brute":                 "brute",
	"iscsi-brute":                    "brute",
	"ldap-brute":                     "brute",
	"membase-brute":                  "brute",
	"memcached-brute":                "brute",
	"metasploit-msgrpc-brute":        "brute",
	"mikrotik-routeros-brute":        "brute",
	"mmouse-brute":                   "brute",
	"mongodb-brute":                  "brute",
	"mqtt-subscribe":                 "brute",
	"ms-sql-brute":                   "brute",
	"mysql-brute":                    "brute",
	"netbus-brute":                   "brute",
	"nexpose-brute":                  "brute",
	"nping-brute":                    "brute",
	"omp2-brute":                     "brute",
	"openvas-otp-brute":              "brute",
	"openlookup-brute":               "brute",
	"oracle-brute":                   "brute",
	"oracle-brute-stealth":           "brute",
	"oracle-sid-brute":               "brute",
	"ovs-agent-version":              "brute",
	"pcanywhere-brute":               "brute",
	"pgsql-brute":                    "brute",
	"pop3-brute":                     "brute",
	"redis-brute":                    "brute",
	"rexec-brute":                    "brute",
	"rlogin-brute":                   "brute",
	"rpcap-brute":                    "brute",
	"rsync-brute":                    "brute",
	"rtsp-url-brute":                 "brute",
	"sip-brute":                      "brute",
	"smb-brute":                      "brute",
	"smb-psexec":                     "brute",
	"smtp-brute":                     "brute",
	"snmp-brute":                     "brute",
	"socks-brute":                    "brute",
	"ssh-brute":                      "brute",
	"svn-brute":                      "brute",
	"telnet-brute":                   "brute",
	"vnc-brute":                      "brute",
	"vmauthd-brute":                  "brute",
	"xmpp-brute":                     "brute",
	"mikrotik-routeros-username-brute": "brute",

	// === DOS/FUZZING SCRIPTS (6 total) - DANGEROUS & NOT USEFUL ===
	"broadcast-avahi-dos":   "dos",
	"dns-fuzz":              "dos",
	"http-form-fuzzer":      "dos",
	"ipv6-ra-flood":         "dos",
	"smb-flood":             "dos",
	"smb-vuln-regsvc-dos":   "dos",

	// === LOW-VALUE INFO GATHERING (select worst offenders) ===
	"broadcast-listener":              "info-gathering",
	"targets-asn":                     "info-gathering",
	"targets-ipv6-multicast-echo":     "info-gathering",
	"targets-ipv6-multicast-invalid":  "info-gathering",
	"targets-ipv6-multicast-mld":      "info-gathering",
	"targets-ipv6-multicast-slaac":    "info-gathering",
	"targets-ipv6-wordlist":           "info-gathering",
	"targets-sniffer":                 "info-gathering",
	"targets-traceroute":              "info-gathering",
	"targets-xml":                     "info-gathering",
	"traceroute-geolocation":          "info-gathering",
	
	// === KNOWN PROBLEMATIC SCRIPTS ===
	"ssh-hostkey": "syntax-error", // Known to have 'ssh' variable issue in Nmap 7.95
}

// IsBlacklisted checks if a script should be excluded
func IsBlacklisted(scriptName string) (bool, string) {
	reason, exists := ScriptBlacklist[scriptName]
	return exists, reason
}

// GetBlacklistStats returns statistics about the blacklist
func GetBlacklistStats() map[string]int {
	stats := make(map[string]int)
	for _, reason := range ScriptBlacklist {
		stats[reason]++
	}
	return stats
}
