package iosxr

import (
	"bufio"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/Cazo-Net/netpipe/internal/model"
	"github.com/Cazo-Net/netpipe/internal/parser"
)

func init() {
	parser.Register("iosxr", &IOSXRParser{})
}

type IOSXRParser struct{}

func (p *IOSXRParser) Name() string {
	return "Cisco IOS-XR Parser"
}

func (p *IOSXRParser) SupportedTypes() []model.DeviceType {
	return []model.DeviceType{model.DeviceIOSXR}
}

func (p *IOSXRParser) Detect(data []byte) bool {
	content := string(data)
	signatures := []string{
		"hostname",
		"router ospf",
		"router bgp",
		"interface GigabitEthernet",
		"ipv4 address",
		"ssh server vrf",
		"domain lookup",
		"domain name",
		"username",
		"aaa new-model",
		"logging",
		"ntp",
		"commit",
		"show running-config",
		"interface MgmtEth",
		"router static",
		"vrf",
		"route-policy",
		"prefix-set",
		"community-set",
		"as-path-set",
		"route-policy",
		"object-group",
	}
	matches := 0
	for _, sig := range signatures {
		if strings.Contains(content, sig) {
			matches++
		}
	}
	return matches >= 3
}

func (p *IOSXRParser) DetectScore(data []byte) int {
	content := string(data)
	signatures := []string{
		"hostname",
		"router ospf",
		"router bgp",
		"interface GigabitEthernet",
		"ipv4 address",
		"ssh server vrf",
		"domain lookup",
		"domain name",
		"username",
		"aaa new-model",
		"logging",
		"ntp",
		"commit",
		"show running-config",
		"interface MgmtEth",
		"router static",
		"vrf",
		"route-policy",
		"prefix-set",
		"community-set",
		"as-path-set",
		"route-policy",
		"object-group",
	}
	score := 0
	for _, sig := range signatures {
		if strings.Contains(content, sig) {
			score++
		}
	}
	return score
}

func (p *IOSXRParser) Parse(r io.Reader, deviceType model.DeviceType) (*model.DeviceConfig, error) {
	device := &model.DeviceConfig{
		DeviceType: model.DeviceIOSXR,
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

func (p *IOSXRParser) processLine(device *model.DeviceConfig, line string, lines []string, idx *int) {
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
	case "interface":
		iface := p.parseInterface(tokens, lines, idx)
		device.AddInterface(iface)
	case "router":
		p.processRouter(device, tokens, lines, idx)
	case "ipv4":
		if len(tokens) > 1 && tokens[1] == "address" {
			// handled in interface
		}
	case "domain":
		if len(tokens) > 1 {
			switch tokens[1] {
			case "lookup":
				device.General.IPDomainLookup = true
			case "name":
				if len(tokens) > 2 {
					device.DNS.DomainName = tokens[2]
				}
			}
		}
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
				}
			}
			device.AddUser(user)
			if user.Password != "" {
				device.AddPassword(model.PasswordEntry{
					Type:     "user-" + user.Username,
					Username: user.Username,
					Hash:     user.Password,
				})
			}
		}
	case "aaa":
		if len(tokens) > 1 && tokens[1] == "new-model" {
			device.AAA.NewModel = true
		}
	case "snmp-server":
		p.processSNMP(device, tokens)
	case "logging":
		p.processLogging(device, tokens)
	case "ntp":
		p.processNTP(device, tokens)
	case "ssh":
		device.SSH.Enabled = true
	case "telnet":
		device.Telnet.Enabled = true
	case "banner":
		if len(tokens) > 1 {
			device.General.Banner = strings.Join(tokens[1:], " ")
		}
	case "vrf":
		// VRF definition - skip content
		for i := *idx + 1; i < len(lines); i++ {
			line := strings.TrimSpace(lines[i])
			if line == "" || !strings.HasPrefix(line, " ") {
				break
			}
			*idx = i
		}
	}
}

func (p *IOSXRParser) parseInterface(tokens []string, lines []string, idx *int) model.Interface {
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
		case "ipv4":
			if len(tokens) > 1 && tokens[1] == "address" && len(tokens) > 2 {
				iface.CIDR = tokens[2]
			}
		case "no":
			if len(tokens) > 1 && tokens[1] == "shutdown" {
				iface.State = "up"
			}
		case "shutdown":
			iface.State = "shutdown"
		case "vrf":
			// VRF on interface
		}
	}

	return iface
}

func (p *IOSXRParser) processRouter(device *model.DeviceConfig, tokens []string, lines []string, idx *int) {
	if len(tokens) < 2 {
		return
	}

	switch tokens[1] {
	case "ospf":
		ospf := &model.OSPFConfig{}
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
			case "area":
				if len(rtokens) > 1 {
					areaID, _ := strconv.Atoi(rtokens[1])
					ospf.Areas = append(ospf.Areas, model.OSPFArea{ID: areaID})
				}
			case "router-id":
				if len(rtokens) > 1 {
					ospf.RouterID = rtokens[1]
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
				if len(rtokens) > 1 {
					neighbor := model.BGPNeighbor{IP: rtokens[1]}
					bgp.Neighbors = append(bgp.Neighbors, neighbor)
				}
			}
		}
		device.Routing.BGP = bgp

	case "static":
		// IOS-XR uses "router static" for static routes
		for i := *idx + 1; i < len(lines); i++ {
			line := strings.TrimSpace(lines[i])
			if line == "" || !strings.HasPrefix(line, " ") {
				break
			}
			*idx = i
		}
	}
}

func (p *IOSXRParser) processSNMP(device *model.DeviceConfig, tokens []string) {
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

func (p *IOSXRParser) processLogging(device *model.DeviceConfig, tokens []string) {
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
		case "level":
			if len(tokens) > 2 {
				device.Logging.ConsoleLevel, _ = strconv.Atoi(tokens[2])
			}
		}
	}
}

func (p *IOSXRParser) processNTP(device *model.DeviceConfig, tokens []string) {
	if len(tokens) > 1 && tokens[1] == "server" && len(tokens) > 2 {
		device.NTP.Servers = append(device.NTP.Servers, model.NTPServer{
			Address: tokens[2],
			Version: 4,
		})
	}
}
