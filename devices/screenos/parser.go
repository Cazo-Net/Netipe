package screenos

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
	parser.Register("screenos", &ScreenOSParser{})
}

type ScreenOSParser struct{}

func (p *ScreenOSParser) Name() string {
	return "Juniper NetScreen ScreenOS Parser"
}

func (p *ScreenOSParser) SupportedTypes() []model.DeviceType {
	return []model.DeviceType{model.DeviceScreenOS}
}

func (p *ScreenOSParser) Detect(data []byte) bool {
	content := string(data)
	signatures := []string{
		"set hostname",
		"set interface",
		"set zone",
		"set address",
		"set policy",
		"set snmp",
		"set ssh",
		"set admin",
		"set clock",
		"set dns",
		"set ntp",
		"set ike",
		"set vpn",
		"set route",
		"unset key",
		"set perf monitor",
		"NetScreen",
		"ScreenOS",
		"ns-500",
		"ns-5200",
	}
	matches := 0
	for _, sig := range signatures {
		if strings.Contains(content, sig) {
			matches++
		}
	}
	return matches >= 3
}

func (p *ScreenOSParser) DetectScore(data []byte) int {
	content := string(data)
	signatures := []string{
		"set hostname",
		"set interface",
		"set zone",
		"set address",
		"set policy",
		"set snmp",
		"set ssh",
		"set admin",
		"set clock",
		"set dns",
		"set ntp",
		"set ike",
		"set vpn",
		"set route",
		"unset key",
		"set perf monitor",
		"NetScreen",
		"ScreenOS",
		"ns-500",
		"ns-5200",
	}
	score := 0
	for _, sig := range signatures {
		if strings.Contains(content, sig) {
			score++
		}
	}
	return score
}

func (p *ScreenOSParser) Parse(r io.Reader, deviceType model.DeviceType) (*model.DeviceConfig, error) {
	device := &model.DeviceConfig{
		DeviceType: model.DeviceScreenOS,
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
		p.processLine(device, line, lines, &i)
	}

	device.SetDefaults()
	return device, nil
}

func (p *ScreenOSParser) processLine(device *model.DeviceConfig, line string, lines []string, idx *int) {
	tokens := strings.Fields(line)
	if len(tokens) == 0 {
		return
	}

	if tokens[0] == "set" && len(tokens) > 1 {
		p.processSet(device, tokens[1:])
	} else if tokens[0] == "unset" && len(tokens) > 1 {
		p.processUnset(device, tokens[1:])
	}
}

func (p *ScreenOSParser) processSet(device *model.DeviceConfig, tokens []string) {
	if len(tokens) < 2 {
		return
	}

	switch tokens[0] {
	case "hostname":
		device.Hostname = tokens[1]
		device.General.Hostname = tokens[1]
		device.DeviceName = tokens[1]
	case "interface":
		p.processInterface(device, tokens)
	case "zone":
		// zone definition
	case "address":
		// address book entry
	case "policy":
		p.processPolicy(device, tokens)
	case "snmp":
		p.processSNMP(device, tokens)
	case "ssh":
		device.SSH.Enabled = true
	case "admin":
		if len(tokens) > 2 {
			switch tokens[1] {
			case "name":
				// admin name
			case "password":
				device.AddPassword(model.PasswordEntry{
					Type: "admin",
					Hash: tokens[2],
				})
			}
		}
	case "clock":
		// clock config
	case "dns":
		if len(tokens) > 2 && tokens[1] == "name-server" {
			device.DNS.Servers = append(device.DNS.Servers, tokens[2])
		}
	case "ntp":
		if len(tokens) > 2 && tokens[1] == "server" {
			device.NTP.Servers = append(device.NTP.Servers, model.NTPServer{
				Address: tokens[2],
				Version: 4,
			})
		}
	case "route":
		// static route
	case "ike":
		// IKE config
	case "vpn":
		// VPN config
	case "perf":
		// performance monitor
	case "syslog":
		// syslog config
	}
}

func (p *ScreenOSParser) processUnset(device *model.DeviceConfig, tokens []string) {
	// handle unset commands
}

func (p *ScreenOSParser) processInterface(device *model.DeviceConfig, tokens []string) {
	if len(tokens) < 3 {
		return
	}

	iface := model.Interface{
		Name: tokens[1],
	}

	for i := 2; i < len(tokens)-1; i += 2 {
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

func (p *ScreenOSParser) processPolicy(device *model.DeviceConfig, tokens []string) {
	acl := model.ACL{
		Type: "screenos-policy",
	}

	for i := 1; i < len(tokens)-1; i += 2 {
		switch tokens[i] {
		case "id":
			acl.Name = "policy-" + tokens[i+1]
		}
	}

	device.AddACL(acl)
}

func (p *ScreenOSParser) processSNMP(device *model.DeviceConfig, tokens []string) {
	if len(tokens) < 2 {
		return
	}

	switch tokens[1] {
	case "community":
		if len(tokens) > 2 {
			device.SNMP.Community = tokens[2]
			device.SNMP.Version = 2
		}
	case "host":
		if len(tokens) > 2 {
			device.SNMP.TrapServers = append(device.SNMP.TrapServers, tokens[2])
		}
	case "name":
		if len(tokens) > 2 {
			device.SNMP.Contact = strings.Join(tokens[2:], " ")
		}
	case "location":
		if len(tokens) > 2 {
			device.SNMP.Location = strings.Join(tokens[2:], " ")
		}
	}
}
