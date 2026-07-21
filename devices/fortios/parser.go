package fortios

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
	parser.Register("fortios", &FortiOSParser{})
}

type FortiOSParser struct{}

func (p *FortiOSParser) Name() string {
	return "Fortinet FortiOS Parser"
}

func (p *FortiOSParser) SupportedTypes() []model.DeviceType {
	return []model.DeviceType{model.DeviceFortiOS}
}

func (p *FortiOSParser) Detect(data []byte) bool {
	content := string(data)
	signatures := []string{
		"set hostname",
		"config system interface",
		"config firewall policy",
		"config firewall address",
		"config system snmp",
		"config system dns",
		"config system ntp",
		"config system global",
		"set admin",
		"config vpn",
		"config wireless",
		"config system settings",
		"config router",
		"set mode static",
		"set vdom",
		"end",
		"FortiGate",
		"FortiGate-",
		"FortiOS",
		"FGT",
	}
	matches := 0
	for _, sig := range signatures {
		if strings.Contains(content, sig) {
			matches++
		}
	}
	return matches >= 3
}

func (p *FortiOSParser) DetectScore(data []byte) int {
	content := string(data)
	signatures := []string{
		"set hostname",
		"config system interface",
		"config firewall policy",
		"config firewall address",
		"config system snmp",
		"config system dns",
		"config system ntp",
		"config system global",
		"set admin",
		"config vpn",
		"config wireless",
		"config system settings",
		"config router",
		"set mode static",
		"set vdom",
		"end",
		"FortiGate",
		"FortiGate-",
		"FortiOS",
		"FGT",
	}
	score := 0
	for _, sig := range signatures {
		if strings.Contains(content, sig) {
			score++
		}
	}
	return score
}

func (p *FortiOSParser) Parse(r io.Reader, deviceType model.DeviceType) (*model.DeviceConfig, error) {
	device := &model.DeviceConfig{
		DeviceType: model.DeviceFortiOS,
		ParsedAt:   time.Now(),
	}

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	device.RawLines = lines

	inSection := ""
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}

		if line == "end" {
			inSection = ""
			continue
		}

		if strings.HasPrefix(line, "config ") {
			inSection = strings.TrimPrefix(line, "config ")
			continue
		}

		tokens := strings.Fields(line)
		if len(tokens) == 0 {
			continue
		}

		if strings.HasPrefix(line, "set ") {
			p.processSet(device, tokens[1:], inSection)
		} else if strings.HasPrefix(line, "edit ") {
			// edit entry
		} else if strings.HasPrefix(line, "next") {
			// next entry
		}
	}

	device.SetDefaults()
	return device, nil
}

func (p *FortiOSParser) processSet(device *model.DeviceConfig, tokens []string, section string) {
	if len(tokens) < 2 {
		return
	}

	key := tokens[0]
	value := strings.Join(tokens[1:], " ")

	switch section {
	case "system interface":
		p.processInterfaceSet(device, key, value)
	case "system global":
		p.processGlobalSet(device, key, value)
	case "firewall policy":
		p.processFirewallSet(device, key, value)
	case "system snmp sysinfo":
		p.processSNMPSet(device, key, value)
	case "system snmp community":
		p.processSNMPCommunitySet(device, key, value)
	case "system ntp":
		p.processNTPSet(device, key, value)
	case "system dns":
		p.processDNSSet(device, key, value)
	case "router static":
		p.processRouteSet(device, key, value)
	case "router ospf":
		p.processOSPFSet(device, key, value)
	default:
		_ = key
		_ = value
	}
}

var currentInterface string

func (p *FortiOSParser) processInterfaceSet(device *model.DeviceConfig, key, value string) {
	switch key {
	case "type":
		// interface type
	case "snmp-index":
		// SNMP index
	case "vdom":
		// VDOM assignment
	case "mode":
		// static/dhcp
	case "ip":
		if parts := strings.Fields(value); len(parts) >= 2 {
			iface := model.Interface{
				Name:   currentInterface,
				CIDR:   parts[0] + "/" + maskToBits(parts[1]),
			}
			device.AddInterface(iface)
		}
	case "allowaccess":
		// allowed management access
		if strings.Contains(value, "ping") {
			// ping allowed
		}
	case "status":
		if value == "down" {
			// interface down
		}
	case "alias":
		// interface description
	case "security-level":
		// security level
	}
}

func (p *FortiOSParser) processGlobalSet(device *model.DeviceConfig, key, value string) {
	switch key {
	case "hostname":
		device.Hostname = value
		device.General.Hostname = value
		device.DeviceName = value
	case "admintimeout":
		minutes, _ := strconv.Atoi(value)
		device.General.ExecTimeout = time.Duration(minutes) * time.Minute
	case "admin-sport":
		// admin port
	case "admin-ssh-grace-time":
		// SSH grace time
	}
}

func (p *FortiOSParser) processFirewallSet(device *model.DeviceConfig, key, value string) {
	_ = key
	_ = value
}

func (p *FortiOSParser) processSNMPSet(device *model.DeviceConfig, key, value string) {
	switch key {
	case "contact-info":
		device.SNMP.Contact = value
	case "location":
		device.SNMP.Location = value
	}
}

func (p *FortiOSParser) processSNMPCommunitySet(device *model.DeviceConfig, key, value string) {
	switch key {
	case "name":
		device.SNMP.Community = value
	case "query-v2c-status":
		device.SNMP.Version = 2
	}
}

func (p *FortiOSParser) processNTPSet(device *model.DeviceConfig, key, value string) {
	switch key {
	case "type":
		// NTP server type
	case "ntpserver":
		if value != "" {
			device.NTP.Servers = append(device.NTP.Servers, model.NTPServer{
				Address: value,
				Version: 4,
			})
		}
	}
}

func (p *FortiOSParser) processDNSSet(device *model.DeviceConfig, key, value string) {
	switch key {
	case "primary":
		device.DNS.Servers = append(device.DNS.Servers, value)
	case "secondary":
		device.DNS.Servers = append(device.DNS.Servers, value)
	case "domain":
		device.DNS.DomainName = value
	}
}

func (p *FortiOSParser) processRouteSet(device *model.DeviceConfig, key, value string) {
	_ = key
	_ = value
}

func (p *FortiOSParser) processOSPFSet(device *model.DeviceConfig, key, value string) {
	if device.Routing.OSPF == nil {
		device.Routing.OSPF = &model.OSPFConfig{}
	}
	switch key {
	case "router-id":
		device.Routing.OSPF.RouterID = value
	}
}

func maskToBits(mask string) string {
	parts := strings.Split(mask, ".")
	if len(parts) != 4 {
		return "32"
	}
	bits := 0
	for _, part := range parts {
		val, _ := strconv.Atoi(part)
		for val > 0 {
			bits += val & 1
			val >>= 1
		}
	}
	return strconv.Itoa(bits)
}
