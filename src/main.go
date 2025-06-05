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
        fmt.Fprintln(os.Stderr, "Usage: nmap-insight [--no-color] <nmap -oN output file>")
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
	    fmt.Printf("\n%s %s: ", header, service)

            fmt.Printf("Required ports %s are present\n",
                joinPorts(sig.Required, green, true, false))

            if len(sig.Optional) > 0 {
                present := presentOptional(openPorts, sig.Optional)
                if len(present) > 0 {
                    fmt.Printf("Optional ports %s are present\n",
                        joinPorts(present, yellow, true, false))
                }
                missing := diff(sig.Optional, present)
                if len(missing) > 0 {
                    fmt.Printf("Optional ports %s are missing\n",
                        joinPorts(missing, "", false, true))
                }
            }
        }
    }

    if !any {
        fmt.Println(style("No composite service signatures recognised.", yellow, false, false))
    }
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
        {Name: "NFS server (rpcbind + nfsd)", Required: []int{111, 2049}, Optional: []int{20048, 4045, 4049}},
        {Name: "FTP (control + data)", Required: []int{20, 21}},
        {Name: "Mail stack (SMTP + POP)", Required: []int{25, 110}},
        {Name: "Mail stack (SMTP + IMAP)", Required: []int{25, 143}},
        {Name: "Mail stack (SMTP + IMAPS)", Required: []int{25, 993}},
        {Name: "SIP / VoIP server", Required: []int{5060}},
        {Name: "Network printer (JetDirect + LPD)", Required: []int{515, 9100}},
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

