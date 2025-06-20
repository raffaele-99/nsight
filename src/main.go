package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// ANSI style fragments
const (
	bold   = "\033[1m"
	green  = "\033[32m"
	yellow = "\033[33m"
	cyan   = "\033[36m"
	faint  = "\033[2m"
	reset  = "\033[0m"
)

var noColor bool // set by flag or NO_COLOR env var

// style applies colour + bold (if colour provided) or faint.
func style(text string, colour string, boldOn bool, faintOn bool) string {
	if noColor {
		return text
	}
	var sb strings.Builder
	if faintOn {
		sb.WriteString(faint)
	} else {
		if boldOn {
			sb.WriteString(bold)
		}
		if colour != "" {
			sb.WriteString(colour)
		}
	}
	sb.WriteString(text)
	sb.WriteString(reset)
	return sb.String()
}

// joinPorts produces "139, 445" with per‑port styling.
func joinPorts(ports []int, colour string, boldOn bool, faintOn bool) string {
	sort.Ints(ports)
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = style(strconv.Itoa(p), colour, boldOn, faintOn)
	}
	return strings.Join(parts, ", ")
}

// Signature for a composite service.
type Signature struct {
	Name     string
	Required []int
	Optional []int
}

func main() {
	flag.BoolVar(&noColor, "no-color", false, "disable ANSI colour output")
	flag.Parse()
	if os.Getenv("NO_COLOR") != "" {
		noColor = true
	}

	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "Usage: nsight [--no-color] <nmap -oN output file>")
		os.Exit(1)
	}

	openPorts, err := parseNmap(flag.Arg(0))
	if err != nil {
		log.Fatalf("cannot parse %s: %v", flag.Arg(0), err)
	}

	if len(openPorts) == 0 {
		fmt.Println(style("No open ports found.", yellow, false, false))
		return
	}

	any := false
	for _, sig := range knownSignatures() {
		if hasAll(openPorts, sig.Required) {
			any = true
			header := style("▶", green, true, false)
			service := style("Possible "+sig.Name+" detected", cyan, true, false)
			fmt.Printf("%s %s: ", header, service)

			fmt.Printf("Required ports %s are present",
				joinPorts(sig.Required, green, true, false))

			if len(sig.Optional) > 0 {
				present := presentOptional(openPorts, sig.Optional)
				if len(present) > 0 {
					fmt.Printf(", optional ports %s are also present",
						joinPorts(present, yellow, true, false))
				}
				missing := diff(sig.Optional, present)
				if len(missing) > 0 {
					fmt.Printf(", optional ports %s are missing",
						joinPorts(missing, "", false, true))
				}
			}
			fmt.Printf("\n")
		}

	}

	if !any {
		fmt.Println(style("No composite service signatures recognised.", yellow, false, false))
	}

	fmt.Printf("\n")
}

// --- helpers -------------------------------------------------------------

func parseNmap(path string) (map[int]struct{}, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	re := regexp.MustCompile(`^(\d+)/tcp\s+open`)
	ports := make(map[int]struct{})
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if m := re.FindStringSubmatch(line); m != nil {
			if p, _ := strconv.Atoi(m[1]); p > 0 {
				ports[p] = struct{}{}
			}
		}
	}
	return ports, s.Err()
}

func knownSignatures() []Signature {
	return []Signature{
		{Name: "SMB / NetBIOS file share", Required: []int{139, 445}},
		{Name: "Active Directory Domain Controller", Required: []int{53, 88, 389, 445, 464}, Optional: []int{636, 3268, 3269, 5985, 9389}},
		{Name: "Windows RPC services (EPM + dynamic RPC)", Required: []int{135}},
		{Name: "Windows Remote Management / WinRM", Required: []int{5985}, Optional: []int{5986}},
		{Name: "NFS server (rpcbind + nfsd)", Required: []int{111, 2049}, Optional: []int{20048, 4045, 4049}},
		{Name: "FTP", Required: []int{21}, Optional: []int{20}},
		{Name: "Mail stack (SMTP + POP)", Required: []int{25, 110}},
		{Name: "Mail stack (SMTP + IMAP)", Required: []int{25, 143}},
		{Name: "Mail stack (SMTP + IMAPS)", Required: []int{25, 993}},
		{Name: "SIP / VoIP server", Required: []int{5060}},
		{Name: "Network printer (JetDirect + LPD)", Required: []int{515, 9100}},
		{Name: "Oracle Database", Required: []int{1521}, Optional: []int{1522, 2483, 2484}},
		{Name: "MySQL / MariaDB", Required: []int{3306}, Optional: []int{33060}},
		{Name: "Microsoft SQL Server", Required: []int{1433}, Optional: []int{}},
		{Name: "PostgreSQL", Required: []int{5432}, Optional: []int{5433}},
		{Name: "IBM Db2 Database", Required: []int{50000}, Optional: []int{50001, 50050}}, // this should be all ports from 50001-50050 but cbf
		{Name: "SAP NetWeaver Application Server", Required: []int{3200, 3300}, Optional: []int{3600, 8000, 8001, 3299}},
		{Name: "Elasticsearch", Required: []int{9200}, Optional: []int{9300}},
		{Name: "Splunk Enterprise", Required: []int{8000, 8089, 9997}, Optional: []int{8088}}, // should also have UDP/514 as optional
		{Name: "VMware vCenter Server", Required: []int{443}, Optional: []int{5480, 902}},
		{Name: "MongoDB Database", Required: []int{27017}, Optional: []int{27018, 27019}},
		{Name: "Redis", Required: []int{6379}, Optional: []int{26379, 16379}},
		{Name: "Apache Cassandra", Required: []int{9042}, Optional: []int{7000, 9160}},
	}
}

func hasAll(set map[int]struct{}, req []int) bool {
	for _, p := range req {
		if _, ok := set[p]; !ok {
			return false
		}
	}
	return true
}

func presentOptional(set map[int]struct{}, opt []int) []int {
	var present []int
	for _, p := range opt {
		if _, ok := set[p]; ok {
			present = append(present, p)
		}
	}
	return present
}

func diff(all, subset []int) []int {
	m := make(map[int]struct{}, len(subset))
	for _, p := range subset {
		m[p] = struct{}{}
	}
	var out []int
	for _, p := range all {
		if _, ok := m[p]; !ok {
			out = append(out, p)
		}
	}
	return out
}
