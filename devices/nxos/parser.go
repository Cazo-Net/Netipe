package nxos

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
	parser.Register("nxos", &NXOSParser{})
}

type NXOSParser struct{}

func (p *NXOSParser) Name() string {
	return "Cisco NX-OS Parser"
}

func (p *NXOSParser) SupportedTypes() []model.DeviceType {
	return []model.DeviceType{model.DeviceNXOS}
}

func (p *NXOSParser) Detect(data []byte) bool {
	content := string(data)
	signatures := []string{
		"feature ospf",
		"feature bgp",
		"feature eigrp",
		"feature interface-vlan",
		"feature lacp",
		"feature vpc",
		"feature hsrp",
		"nxos",
		"show running-config",
		"switchport mode",
		"interface Ethernet",
		"interface mgmt0",
		"vpc domain",
		"spanning-tree mode",
		"vlan database",
		"interface Vlan",
		"ip route",
		"router ospf",
		"router bgp",
	}
	matches := 0
	for _, sig := range signatures {
		if strings.Contains(content, sig) {
			matches++
		}
	}
	return matches >= 3
}

func (p *NXOSParser) DetectScore(data []byte) int {
	content := string(data)
	signatures := []string{
		"feature ospf",
		"feature bgp",
		"feature eigrp",
		"feature interface-vlan",
		"feature lacp",
		"feature vpc",
		"feature hsrp",
		"nxos",
		"show running-config",
		"switchport mode",
		"interface Ethernet",
		"interface mgmt0",
		"vpc domain",
		"spanning-tree mode",
		"vlan database",
		"interface Vlan",
		"ip route",
		"router ospf",
		"router bgp",
	}
	score := 0
	for _, sig := range signatures {
		if strings.Contains(content, sig) {
			score++
		}
	}
	return score
}

func (p *NXOSParser) Parse(r io.Reader, deviceType model.DeviceType) (*model.DeviceConfig, error) {
	device := &model.DeviceConfig{
		DeviceType: model.DeviceNXOS,
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

func (p *NXOSParser) processLine(device *model.DeviceConfig, line string, lines []string, idx *int) {
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
	case "feature":
		p.processFeature(device, tokens)
	case "interface":
		iface := p.parseInterface(tokens, lines, idx)
		device.AddInterface(iface)
	case "router":
		p.processRouter(device, tokens, lines, idx)
	case "vlan":
		// VLAN config
	case "vpc":
		// VPC domain config
	case "ip":
		p.processIP(device, tokens)
	case "access-list":
		p.processACL(device, tokens)
	case "spanning-tree":
		// spanning tree config
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
				case "role":
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
	case "enable":
		if len(tokens) > 1 && tokens[1] == "secret" {
			device.General.EnableSecret = strings.Join(tokens[2:], " ")
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
	case "telnet":
		device.Telnet.Enabled = true
	case "ssh":
		device.SSH.Enabled = true
	case "aaa":
		p.processAAA(device, tokens)
	}
}

func (p *NXOSParser) processFeature(device *model.DeviceConfig, tokens []string) {
	if len(tokens) < 2 {
		return
	}
	feature := tokens[1]
	switch feature {
	case "telnet":
		device.Telnet.Enabled = true
	case "ssh":
		device.SSH.Enabled = true
	case "http-server":
		device.General.HTTPServer = true
	case "ospf":
		device.Routing.OSPF = &model.OSPFConfig{}
	case "bgp":
		device.Routing.BGP = &model.BGPConfig{}
	case "eigrp":
		device.Routing.EIGRP = &model.EIGRPConfig{}
	case "hsrp":
		// HSRP feature
	case "vpc":
		// VPC feature
	case "lacp":
		// LACP feature
	}
}

func (p *NXOSParser) parseInterface(tokens []string, lines []string, idx *int) model.Interface {
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
		case "switchport":
			iface.Switchport = true
		case "ip":
			if len(tokens) > 2 && tokens[1] == "address" {
				iface.CIDR = tokens[2]
			}
		case "no":
			if len(tokens) > 1 && tokens[1] == "shutdown" {
				iface.State = "up"
			}
		case "shutdown":
			iface.State = "shutdown"
		case "vlan":
			if len(tokens) > 1 {
				iface.VLAN, _ = strconv.Atoi(tokens[1])
			}
		case "vpc":
			// VPC member port
		case "spanning-tree":
			// spanning tree port config
		}
	}

	return iface
}

func (p *NXOSParser) processRouter(device *model.DeviceConfig, tokens []string, lines []string, idx *int) {
	if len(tokens) < 2 {
		return
	}

	switch tokens[1] {
	case "ospf":
		ospf := &model.OSPFConfig{ProcessID: 1}
		if len(tokens) > 2 {
			ospf.ProcessID, _ = strconv.Atoi(tokens[2])
		}
		device.Routing.OSPF = ospf
	case "bgp":
		bgp := &model.BGPConfig{}
		if len(tokens) > 2 {
			bgp.ASN, _ = strconv.Atoi(tokens[2])
		}
		device.Routing.BGP = bgp
	case "eigrp":
		eigrp := &model.EIGRPConfig{}
		if len(tokens) > 2 {
			eigrp.ASN, _ = strconv.Atoi(tokens[2])
		}
		device.Routing.EIGRP = eigrp
	}
}

func (p *NXOSParser) processIP(device *model.DeviceConfig, tokens []string) {
	if len(tokens) < 2 {
		return
	}
	switch tokens[1] {
	case "route":
		// static route
	case "domain":
		if len(tokens) > 2 && tokens[2] == "name" && len(tokens) > 3 {
			device.DNS.DomainName = tokens[3]
		}
	case "name-server":
		if len(tokens) > 2 {
			device.DNS.Servers = append(device.DNS.Servers, tokens[2])
		}
	}
}

func (p *NXOSParser) processACL(device *model.DeviceConfig, tokens []string) {
	if len(tokens) < 2 {
		return
	}
	acl := model.ACL{
		Name: tokens[1],
		Type: "extended",
	}
	device.AddACL(acl)
}

func (p *NXOSParser) processSNMP(device *model.DeviceConfig, tokens []string) {
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

func (p *NXOSParser) processLogging(device *model.DeviceConfig, tokens []string) {
	device.Logging.Enabled = true
	if len(tokens) > 1 {
		switch tokens[1] {
		case "server":
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

func (p *NXOSParser) processNTP(device *model.DeviceConfig, tokens []string) {
	if len(tokens) > 1 && tokens[1] == "server" && len(tokens) > 2 {
		device.NTP.Servers = append(device.NTP.Servers, model.NTPServer{
			Address: tokens[2],
			Version: 4,
		})
	}
}

func (p *NXOSParser) processAAA(device *model.DeviceConfig, tokens []string) {
	if len(tokens) > 1 && tokens[1] == "new-model" {
		device.AAA.NewModel = true
	}
}
