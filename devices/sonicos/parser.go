package sonicos

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
	parser.Register("sonicos", &SonicOSParser{})
}

type SonicOSParser struct{}

func (p *SonicOSParser) Name() string {
	return "SonicWall SonicOS Parser"
}

func (p *SonicOSParser) SupportedTypes() []model.DeviceType {
	return []model.DeviceType{model.DeviceSonicOS}
}

func (p *SonicOSParser) Detect(data []byte) bool {
	content := string(data)
	signatures := []string{
		"set hostname",
		"set snmp",
		"set ssh",
		"set telnet",
		"set interface",
		"set access-list",
		"set vpn",
		"set nat",
		"set route",
		"set dns",
		"set ntp",
		"set admin",
		"SonicWall",
		"SonicOS",
		"sonicwall",
	}
	matches := 0
	for _, sig := range signatures {
		if strings.Contains(content, sig) {
			matches++
		}
	}
	return matches >= 3
}

func (p *SonicOSParser) DetectScore(data []byte) int {
	content := string(data)
	signatures := []string{
		"set hostname",
		"set snmp",
		"set ssh",
		"set telnet",
		"set interface",
		"set access-list",
		"set vpn",
		"set nat",
		"set route",
		"set dns",
		"set ntp",
		"set admin",
		"SonicWall",
		"SonicOS",
		"sonicwall",
	}
	score := 0
	for _, sig := range signatures {
		if strings.Contains(content, sig) {
			score++
		}
	}
	return score
}

func (p *SonicOSParser) Parse(r io.Reader, deviceType model.DeviceType) (*model.DeviceConfig, error) {
	device := &model.DeviceConfig{
		DeviceType: model.DeviceSonicOS,
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
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p.processLine(device, line)
	}

	device.SetDefaults()
	return device, nil
}

func (p *SonicOSParser) processLine(device *model.DeviceConfig, line string) {
	tokens := strings.Fields(line)
	if len(tokens) < 2 {
		return
	}

	if tokens[0] != "set" {
		return
	}

	switch tokens[1] {
	case "hostname":
		if len(tokens) > 2 {
			device.Hostname = tokens[2]
			device.General.Hostname = tokens[2]
			device.DeviceName = tokens[2]
		}
	case "snmp":
		p.processSNMP(device, tokens)
	case "ssh":
		device.SSH.Enabled = true
	case "telnet":
		device.Telnet.Enabled = true
	case "interface":
		p.processInterface(device, tokens)
	case "access-list":
		p.processACL(device, tokens)
	case "route":
		// static route
	case "dns":
		if len(tokens) > 3 && tokens[2] == "name-server" {
			device.DNS.Servers = append(device.DNS.Servers, tokens[3])
		}
	case "ntp":
		if len(tokens) > 3 && tokens[2] == "server" {
			device.NTP.Servers = append(device.NTP.Servers, model.NTPServer{
				Address: tokens[3],
				Version: 4,
			})
		}
	case "admin":
		if len(tokens) > 3 && tokens[2] == "password" {
			device.AddPassword(model.PasswordEntry{
				Type: "admin",
				Hash: tokens[3],
			})
		}
	}
}

func (p *SonicOSParser) processSNMP(device *model.DeviceConfig, tokens []string) {
	if len(tokens) < 4 {
		return
	}

	switch tokens[2] {
	case "community":
		if len(tokens) > 3 {
			device.SNMP.Community = tokens[3]
			device.SNMP.Version = 2
		}
	case "host":
		if len(tokens) > 3 {
			device.SNMP.TrapServers = append(device.SNMP.TrapServers, tokens[3])
		}
	case "contact":
		if len(tokens) > 3 {
			device.SNMP.Contact = strings.Join(tokens[3:], " ")
		}
	case "location":
		if len(tokens) > 3 {
			device.SNMP.Location = strings.Join(tokens[3:], " ")
		}
	}
}

func (p *SonicOSParser) processInterface(device *model.DeviceConfig, tokens []string) {
	if len(tokens) < 4 {
		return
	}

	iface := model.Interface{
		Name: tokens[2],
	}

	for i := 3; i < len(tokens)-1; i += 2 {
		switch tokens[i] {
		case "ip":
			iface.CIDR = tokens[i+1]
		case "zone":
			iface.Zone = tokens[i+1]
		case "vlan":
			iface.VLAN, _ = strconv.Atoi(tokens[i+1])
		}
	}

	device.AddInterface(iface)
}

func (p *SonicOSParser) processACL(device *model.DeviceConfig, tokens []string) {
	if len(tokens) < 3 {
		return
	}

	acl := model.ACL{
		Name: tokens[2],
		Type: "sonicos-access-list",
	}

	acl.AddRule(model.ACLRule{
		Action: "permit",
		Enabled: true,
	})

	device.AddACL(acl)
}
