package eos

import (
	"bufio"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/netpipe/netpipe/internal/model"
	"github.com/netpipe/netpipe/internal/parser"
)

func init() {
	parser.Register("eos", &EOSParser{})
}

type EOSParser struct{}

func (p *EOSParser) Name() string {
	return "Arista EOS Parser"
}

func (p *EOSParser) SupportedTypes() []model.DeviceType {
	return []model.DeviceType{model.DeviceEOS}
}

func (p *EOSParser) Detect(data []byte) bool {
	content := string(data)
	signatures := []string{
		"hostname",
		"interface Ethernet",
		"interface Management",
		"interface Vlan",
		"router ospf",
		"router bgp",
		"vlan",
		"ip name-server",
		"logging buffered",
		"ntp server",
		"snmp-server community",
		"username",
		"enable secret",
		"management api",
		"agent",
		"daemon",
		"Arista",
		"EOS-",
	}
	uniqueSignatures := []string{
		"management api",
		"Arista",
		"EOS-",
		"agent",
		"daemon",
	}
	matches := 0
	for _, sig := range signatures {
		if strings.Contains(content, sig) {
			matches++
		}
	}
	uniqueMatches := 0
	for _, sig := range uniqueSignatures {
		if strings.Contains(content, sig) {
			uniqueMatches++
		}
	}
	return matches >= 5 && uniqueMatches >= 1
}

func (p *EOSParser) DetectScore(data []byte) int {
	content := string(data)
	signatures := []string{
		"hostname",
		"interface Ethernet",
		"interface Management",
		"interface Vlan",
		"router ospf",
		"router bgp",
		"vlan",
		"ip name-server",
		"logging buffered",
		"ntp server",
		"snmp-server community",
		"username",
		"enable secret",
		"management api",
		"agent",
		"daemon",
		"Arista",
		"EOS-",
	}
	uniqueSignatures := []string{
		"management api",
		"Arista",
		"EOS-",
		"agent",
		"daemon",
	}
	score := 0
	for _, sig := range signatures {
		if strings.Contains(content, sig) {
			score++
		}
	}
	for _, sig := range uniqueSignatures {
		if strings.Contains(content, sig) {
			score++
		}
	}
	return score
}

func (p *EOSParser) Parse(r io.Reader, deviceType model.DeviceType) (*model.DeviceConfig, error) {
	device := &model.DeviceConfig{
		DeviceType: model.DeviceEOS,
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
		if line == "" || strings.HasPrefix(line, "!") {
			continue
		}
		p.processLine(device, line, lines, &i)
	}

	device.SetDefaults()
	return device, nil
}

func (p *EOSParser) processLine(device *model.DeviceConfig, line string, lines []string, idx *int) {
	tokens := strings.Fields(line)
	if len(tokens) == 0 {
		return
	}

	switch tokens[0] {
	case "hostname":
		if len(tokens) > 1 {
			device.Hostname = tokens[1]
			device.General.Hostname = tokens[1]
			device.DeviceName = tokens[1]
		}
	case "version":
		if len(tokens) > 1 {
			device.Version = tokens[1]
		}
	case "enable":
		if len(tokens) > 2 && tokens[1] == "secret" {
			device.General.EnableSecret = strings.Join(tokens[2:], " ")
			device.AddPassword(model.PasswordEntry{
				Type: "enable-secret",
				Hash: device.General.EnableSecret,
			})
		} else if len(tokens) > 1 && tokens[1] == "password" {
			device.General.EnablePassword = strings.Join(tokens[2:], " ")
		}
	case "interface":
		iface := p.parseInterface(tokens, lines, idx)
		device.AddInterface(iface)
	case "router":
		p.processRouter(device, tokens, lines, idx)
	case "ip":
		p.processIP(device, tokens)
	case "access-list":
		p.processACL(device, tokens)
	case "username":
		if len(tokens) > 1 {
			user := model.UserEntry{
				Username: tokens[1],
				Local:    true,
			}
			for i := 2; i < len(tokens); i++ {
				switch tokens[i] {
				case "password":
					if i+1 < len(tokens) {
						user.Password = tokens[i+1]
						i++
					}
				case "secret":
					if i+1 < len(tokens) {
						user.Password = tokens[i+1]
						user.Secret = true
						i++
					}
				case "privilege":
					if i+1 < len(tokens) {
						user.Privilege, _ = strconv.Atoi(tokens[i+1])
						i++
					}
				}
			}
			if user.Password != "" {
				device.AddPassword(model.PasswordEntry{
					Type:     "user-" + user.Username,
					Username: user.Username,
					Hash:     user.Password,
				})
			}
			device.AddUser(user)
		}
	case "snmp-server":
		p.processSNMP(device, tokens)
	case "logging":
		p.processLogging(device, tokens)
	case "banner":
		if len(tokens) > 1 {
			device.General.Banner = strings.Join(tokens[1:], " ")
		}
	case "ntp":
		p.processNTP(device, tokens)
	case "management":
		// management API config
	case "agent":
		// agent config
	case "spanning-tree":
		// spanning tree config
	case "vlan":
		// VLAN config
	}
}

func (p *EOSParser) parseInterface(tokens []string, lines []string, idx *int) model.Interface {
	iface := model.Interface{}
	if len(tokens) > 1 {
		iface.Name = tokens[1]
	}

	for i := *idx + 1; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" || !strings.HasPrefix(line, " ") {
			break
		}
		*idx = i
		line = strings.TrimSpace(line)
		tokens := strings.Fields(line)
		if len(tokens) == 0 {
			continue
		}

		switch tokens[0] {
		case "description":
			iface.Description = strings.TrimPrefix(line, "description ")
		case "ip":
			if len(tokens) > 2 && tokens[1] == "address" {
				iface.CIDR = tokens[2]
			}
		case "switchport":
			iface.Switchport = true
		case "no":
			if len(tokens) > 1 && tokens[1] == "shutdown" {
				iface.State = "up"
			} else if len(tokens) > 1 && tokens[1] == "switchport" {
				iface.Switchport = false
			}
		case "shutdown":
			iface.State = "shutdown"
		case "vlan":
			if len(tokens) > 1 {
				iface.VLAN, _ = strconv.Atoi(tokens[1])
			}
		case "spanning-tree":
			// spanning tree port config
		}
	}

	return iface
}

func (p *EOSParser) processRouter(device *model.DeviceConfig, tokens []string, lines []string, idx *int) {
	if len(tokens) < 2 {
		return
	}

	switch tokens[1] {
	case "ospf":
		ospf := &model.OSPFConfig{ProcessID: 1}
		if len(tokens) > 2 {
			ospf.ProcessID, _ = strconv.Atoi(tokens[2])
		}
		for i := *idx + 1; i < len(lines); i++ {
			line := strings.TrimSpace(lines[i])
			if line == "" || !strings.HasPrefix(line, " ") {
				break
			}
			*idx = i
			line = strings.TrimSpace(line)
			rtokens := strings.Fields(line)
			if len(rtokens) == 0 {
				continue
			}
			switch rtokens[0] {
			case "router-id":
				if len(rtokens) > 1 {
					ospf.RouterID = rtokens[1]
				}
			case "area":
				if len(rtokens) > 1 {
					areaID, _ := strconv.Atoi(rtokens[1])
					ospf.Areas = append(ospf.Areas, model.OSPFArea{ID: areaID})
				}
			case "passive-interface":
				if len(rtokens) > 1 {
					ospf.PassiveInterfaces = append(ospf.PassiveInterfaces, rtokens[1])
				}
			}
		}
		device.Routing.OSPF = ospf

	case "bgp":
		bgp := &model.BGPConfig{}
		if len(tokens) > 2 {
			bgp.ASN, _ = strconv.Atoi(tokens[2])
		}
		for i := *idx + 1; i < len(lines); i++ {
			line := strings.TrimSpace(lines[i])
			if line == "" || !strings.HasPrefix(line, " ") {
				break
			}
			*idx = i
			line = strings.TrimSpace(line)
			rtokens := strings.Fields(line)
			if len(rtokens) == 0 {
				continue
			}
			switch rtokens[0] {
			case "neighbor":
				if len(rtokens) > 2 && rtokens[2] == "remote-as" && len(rtokens) > 3 {
					neighbor := model.BGPNeighbor{
						IP:       rtokens[1],
						RemoteAS: atoi(rtokens[3]),
					}
					bgp.Neighbors = append(bgp.Neighbors, neighbor)
				}
			}
		}
		device.Routing.BGP = bgp
	}
}

func (p *EOSParser) processIP(device *model.DeviceConfig, tokens []string) {
	if len(tokens) < 2 {
		return
	}
	switch tokens[1] {
	case "name-server":
		if len(tokens) > 2 {
			device.DNS.Servers = append(device.DNS.Servers, tokens[2])
		}
	case "domain-name":
		if len(tokens) > 2 {
			device.DNS.DomainName = tokens[2]
		}
	case "route":
		// static route
	}
}

func (p *EOSParser) processACL(device *model.DeviceConfig, tokens []string) {
	if len(tokens) < 2 {
		return
	}
	acl := model.ACL{
		Name: tokens[1],
		Type: "extended",
	}
	device.AddACL(acl)
}

func (p *EOSParser) processSNMP(device *model.DeviceConfig, tokens []string) {
	if len(tokens) < 2 {
		return
	}
	switch tokens[1] {
	case "community":
		if len(tokens) > 2 {
			device.SNMP.Community = tokens[2]
			device.SNMP.Version = 2
		}
	case "contact":
		if len(tokens) > 2 {
			device.SNMP.Contact = strings.Join(tokens[2:], " ")
		}
	case "location":
		if len(tokens) > 2 {
			device.SNMP.Location = strings.Join(tokens[2:], " ")
		}
	case "host":
		if len(tokens) > 2 {
			device.SNMP.TrapServers = append(device.SNMP.TrapServers, tokens[2])
		}
	}
}

func (p *EOSParser) processLogging(device *model.DeviceConfig, tokens []string) {
	device.Logging.Enabled = true
	if len(tokens) > 1 {
		switch tokens[1] {
		case "buffer":
			if len(tokens) > 2 {
				device.Logging.BufferSize, _ = strconv.Atoi(tokens[2])
			}
		case "host":
			if len(tokens) > 2 {
				device.Logging.SyslogServers = append(device.Logging.SyslogServers, tokens[2])
			}
		}
	}
}

func (p *EOSParser) processNTP(device *model.DeviceConfig, tokens []string) {
	if len(tokens) > 1 && tokens[1] == "server" && len(tokens) > 2 {
		device.NTP.Servers = append(device.NTP.Servers, model.NTPServer{
			Address: tokens[2],
			Version: 4,
		})
	}
}

func atoi(s string) int {
	val, _ := strconv.Atoi(s)
	return val
}
