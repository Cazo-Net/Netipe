package junos

import (
	"bufio"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/Cazo-Net/Netipe/internal/model"
	"github.com/Cazo-Net/Netipe/internal/parser"
)

func init() {
	parser.Register("junos", &JunosParser{})
}

type JunosParser struct{}

func (p *JunosParser) Name() string {
	return "Juniper Junos Parser"
}

func (p *JunosParser) SupportedTypes() []model.DeviceType {
	return []model.DeviceType{model.DeviceJunos}
}

func (p *JunosParser) Detect(data []byte) bool {
	content := string(data)
	signatures := []string{
		"system {",
		"interfaces {",
		"protocols {",
		"routing-options {",
		"firewall {",
		"security {",
		"snmp {",
		"ssh {",
		"telnet",
		"host-name",
		"services {",
		"syslog {",
		"ntp {",
		"commit",
		"set system",
		"set interfaces",
		"set protocols",
		"set security",
		"set firewall",
		"set routing-options",
		"version JunOS",
		"junos-version",
	}
	matches := 0
	for _, sig := range signatures {
		if strings.Contains(content, sig) {
			matches++
		}
	}
	return matches >= 3
}

func (p *JunosParser) DetectScore(data []byte) int {
	content := string(data)
	signatures := []string{
		"system {",
		"interfaces {",
		"protocols {",
		"routing-options {",
		"firewall {",
		"security {",
		"snmp {",
		"ssh {",
		"telnet",
		"host-name",
		"services {",
		"syslog {",
		"ntp {",
		"commit",
		"set system",
		"set interfaces",
		"set protocols",
		"set security",
		"set firewall",
		"set routing-options",
		"version JunOS",
		"junos-version",
	}
	score := 0
	for _, sig := range signatures {
		if strings.Contains(content, sig) {
			score++
		}
	}
	return score
}

func (p *JunosParser) Parse(r io.Reader, deviceType model.DeviceType) (*model.DeviceConfig, error) {
	device := &model.DeviceConfig{
		DeviceType: model.DeviceJunos,
		ParsedAt:   time.Now(),
	}

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	device.RawLines = lines

	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		p.processLine(device, line, lines, &i)
	}

	device.SetDefaults()
	return device, nil
}

func (p *JunosParser) processLine(device *model.DeviceConfig, line string, lines []string, idx *int) {
	tokens := strings.Fields(line)
	if len(tokens) == 0 {
		return
	}

	if strings.HasPrefix(line, "set ") {
		p.processSetCommand(device, tokens[1:])
		return
	}

	switch tokens[0] {
	case "system":
		p.processSystem(device, lines, idx)
	case "interfaces":
		p.processInterfaces(device, lines, idx)
	case "protocols":
		p.processProtocols(device, lines, idx)
	case "routing-options":
		p.processRoutingOptions(device, lines, idx)
	case "security":
		p.processSecurity(device, lines, idx)
	case "firewall":
		p.processFirewall(device, lines, idx)
	case "snmp":
		p.processSNMP(device, lines, idx)
	}
}

func (p *JunosParser) processSetCommand(device *model.DeviceConfig, tokens []string) {
	if len(tokens) == 0 {
		return
	}

	switch tokens[0] {
	case "system":
		if len(tokens) > 1 {
			switch tokens[1] {
			case "host-name":
				if len(tokens) > 2 {
					device.Hostname = tokens[2]
					device.General.Hostname = tokens[2]
					device.DeviceName = tokens[2]
				}
			case "services":
				if len(tokens) > 2 {
					switch tokens[2] {
					case "ssh":
						device.SSH.Enabled = true
					case "telnet":
						device.Telnet.Enabled = true
					}
				}
			case "login":
				if len(tokens) > 2 && tokens[2] == "user" && len(tokens) > 3 {
					user := model.UserEntry{
						Username: tokens[3],
						Local:    true,
					}
					device.AddUser(user)
				}
			}
		}
	case "interfaces":
		if len(tokens) > 1 {
			iface := model.Interface{Name: tokens[1]}
			for i := 2; i < len(tokens); i++ {
				switch tokens[i] {
				case "unit":
					// interface unit
				case "family":
					if i+1 < len(tokens) && tokens[i+1] == "inet" {
						if i+2 < len(tokens) && tokens[i+2] == "address" && i+3 < len(tokens) {
							iface.CIDR = tokens[3]
							i += 2
						}
					}
				}
			}
			device.AddInterface(iface)
		}
	case "protocols":
		if len(tokens) > 1 {
			switch tokens[1] {
			case "ospf":
				if device.Routing.OSPF == nil {
					device.Routing.OSPF = &model.OSPFConfig{}
				}
			case "bgp":
				if device.Routing.BGP == nil {
					device.Routing.BGP = &model.BGPConfig{}
				}
			}
		}
	case "snmp":
		if len(tokens) > 1 {
			switch tokens[1] {
			case "community":
				if len(tokens) > 2 {
					device.SNMP.Community = tokens[2]
					device.SNMP.Version = 2
				}
			case "trap":
				if len(tokens) > 2 {
					device.SNMP.TrapServers = append(device.SNMP.TrapServers, tokens[2])
				}
			}
		}
	case "security":
		// security policies
	}
}

func (p *JunosParser) processSystem(device *model.DeviceConfig, lines []string, idx *int) {
	for i := *idx + 1; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			break
		}
		depth := p.getDepth(lines[i])
		if depth == 0 {
			break
		}
		*idx = i
		tokens := strings.Fields(line)
		if len(tokens) == 0 {
			continue
		}

		switch tokens[0] {
		case "host-name":
			if len(tokens) > 1 {
				device.Hostname = tokens[1]
				device.General.Hostname = tokens[1]
				device.DeviceName = tokens[1]
			}
		case "services":
			// nested services
		case "login":
			// nested login
		case "syslog":
			// nested syslog
		case "ntp":
			// nested ntp
		case "radius-server":
			// RADIUS config
		case "tacplus-server":
			// TACACS+ config
		}
	}
}

func (p *JunosParser) processInterfaces(device *model.DeviceConfig, lines []string, idx *int) {
	for i := *idx + 1; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			break
		}
		depth := p.getDepth(lines[i])
		if depth == 0 {
			break
		}
		*idx = i
		tokens := strings.Fields(line)
		if len(tokens) == 0 {
			continue
		}

		iface := model.Interface{
			Name: tokens[0],
		}

		for j := i + 1; j < len(lines); j++ {
			il := strings.TrimSpace(lines[j])
			if il == "" || p.getDepth(lines[j]) <= 1 {
				break
			}
			itokens := strings.Fields(il)
			if len(itokens) == 0 {
				continue
			}
			switch itokens[0] {
			case "description":
				iface.Description = strings.TrimPrefix(il, "description ")
			case "family":
				if len(itokens) > 1 && itokens[1] == "inet" && len(itokens) > 2 && itokens[2] == "address" {
					if len(itokens) > 3 {
						iface.CIDR = itokens[3]
					}
				}
			case "unit":
				if len(itokens) > 1 && itokens[1] == "0" {
					// unit 0
				}
			case "vlan-tagging":
				iface.Switchport = true
			case "speed":
				// speed config
			}
		}

		device.AddInterface(iface)
	}
}

func (p *JunosParser) processProtocols(device *model.DeviceConfig, lines []string, idx *int) {
	for i := *idx + 1; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			break
		}
		depth := p.getDepth(lines[i])
		if depth == 0 {
			break
		}
		*idx = i
		tokens := strings.Fields(line)
		if len(tokens) == 0 {
			continue
		}

		switch tokens[0] {
		case "ospf":
			if device.Routing.OSPF == nil {
				device.Routing.OSPF = &model.OSPFConfig{}
			}
			for j := i + 1; j < len(lines); j++ {
				pl := strings.TrimSpace(lines[j])
				if pl == "" || p.getDepth(lines[j]) <= 1 {
					break
				}
				ptokens := strings.Fields(pl)
				if len(ptokens) == 0 {
					continue
				}
				switch ptokens[0] {
				case "area":
					if len(ptokens) > 1 {
						areaID, _ := strconv.Atoi(ptokens[1])
						device.Routing.OSPF.Areas = append(device.Routing.OSPF.Areas, model.OSPFArea{ID: areaID})
					}
				}
			}
		case "bgp":
			if device.Routing.BGP == nil {
				device.Routing.BGP = &model.BGPConfig{}
			}
			for j := i + 1; j < len(lines); j++ {
				pl := strings.TrimSpace(lines[j])
				if pl == "" || p.getDepth(lines[j]) <= 1 {
					break
				}
				ptokens := strings.Fields(pl)
				if len(ptokens) == 0 {
					continue
				}
				switch ptokens[0] {
				case "group":
					// BGP group config
				case "neighbor":
					if len(ptokens) > 1 {
						neighbor := model.BGPNeighbor{IP: ptokens[1]}
						device.Routing.BGP.Neighbors = append(device.Routing.BGP.Neighbors, neighbor)
					}
				}
			}
		case "static":
			// static routes
		case "rip":
			// RIP config
		}
	}
}

func (p *JunosParser) processRoutingOptions(device *model.DeviceConfig, lines []string, idx *int) {
	for i := *idx + 1; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			break
		}
		depth := p.getDepth(lines[i])
		if depth == 0 {
			break
		}
		*idx = i
		tokens := strings.Fields(line)
		if len(tokens) == 0 {
			continue
		}

		switch tokens[0] {
		case "static":
			// static route definitions
		case "router-id":
			if len(tokens) > 1 {
				if device.Routing.OSPF != nil {
					device.Routing.OSPF.RouterID = tokens[1]
				}
			}
		case "autonomous-system":
			if len(tokens) > 1 {
				device.Routing.BGP.ASN, _ = strconv.Atoi(tokens[1])
			}
		}
	}
}

func (p *JunosParser) processSecurity(device *model.DeviceConfig, lines []string, idx *int) {
	for i := *idx + 1; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			break
		}
		depth := p.getDepth(lines[i])
		if depth == 0 {
			break
		}
		*idx = i
	}
}

func (p *JunosParser) processFirewall(device *model.DeviceConfig, lines []string, idx *int) {
	for i := *idx + 1; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			break
		}
		depth := p.getDepth(lines[i])
		if depth == 0 {
			break
		}
		*idx = i
	}
}

func (p *JunosParser) processSNMP(device *model.DeviceConfig, lines []string, idx *int) {
	for i := *idx + 1; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			break
		}
		depth := p.getDepth(lines[i])
		if depth == 0 {
			break
		}
		*idx = i
		tokens := strings.Fields(line)
		if len(tokens) == 0 {
			continue
		}

		switch tokens[0] {
		case "community":
			if len(tokens) > 1 {
				device.SNMP.Community = tokens[1]
				device.SNMP.Version = 2
			}
		case "trap":
			if len(tokens) > 1 {
				device.SNMP.TrapServers = append(device.SNMP.TrapServers, tokens[1])
			}
		case "contact":
			if len(tokens) > 1 {
				device.SNMP.Contact = strings.Trim(strings.Join(tokens[1:], " "), "\"")
			}
		case "location":
			if len(tokens) > 1 {
				device.SNMP.Location = strings.Trim(strings.Join(tokens[1:], " "), "\"")
			}
		}
	}
}

func (p *JunosParser) getDepth(line string) int {
	count := 0
	for _, c := range line {
		if c == '{' {
			count++
		} else if c == '}' {
			count--
		}
	}
	return count
}
