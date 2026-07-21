package iosxe

import (
	"bufio"
	"io"
	"strings"
	"time"

	"github.com/Cazo-Net/Netipe/internal/model"
	"github.com/Cazo-Net/Netipe/internal/parser"
)

func init() {
	parser.Register("iosxe", &IOSXEParser{})
}

type IOSXEParser struct{}

func (p *IOSXEParser) Name() string {
	return "Cisco IOS-XE Parser"
}

func (p *IOSXEParser) SupportedTypes() []model.DeviceType {
	return []model.DeviceType{model.DeviceIOSXE}
}

func (p *IOSXEParser) Detect(data []byte) bool {
	content := string(data)
	signatures := []string{
		"platform",
		"service timestamps debug datetime msec",
		"service timestamps log datetime msec",
		"no service pad",
		"hostname",
		"boot-start-marker",
		"boot-end-marker",
		"vrf definition",
		"interface GigabitEthernet",
		"router ospf",
		"router bgp",
		"ntp server",
		"logging buffered",
		"ntp logging",
		"aa new-model",
		"aaa new-model",
		"license udi",
		"diagnostic",
		"platform software",
		"inventory",
	}
	matches := 0
	for _, sig := range signatures {
		if strings.Contains(content, sig) {
			matches++
		}
	}
	return matches >= 3
}

func (p *IOSXEParser) DetectScore(data []byte) int {
	content := string(data)
	signatures := []string{
		"platform",
		"service timestamps debug datetime msec",
		"service timestamps log datetime msec",
		"no service pad",
		"hostname",
		"boot-start-marker",
		"boot-end-marker",
		"vrf definition",
		"interface GigabitEthernet",
		"router ospf",
		"router bgp",
		"ntp server",
		"logging buffered",
		"ntp logging",
		"aa new-model",
		"aaa new-model",
		"license udi",
		"diagnostic",
		"platform software",
		"inventory",
	}
	score := 0
	for _, sig := range signatures {
		if strings.Contains(content, sig) {
			score++
		}
	}
	return score
}

func (p *IOSXEParser) Parse(r io.Reader, deviceType model.DeviceType) (*model.DeviceConfig, error) {
	device := &model.DeviceConfig{
		DeviceType: model.DeviceIOSXE,
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

func (p *IOSXEParser) processLine(device *model.DeviceConfig, line string, lines []string, idx *int) {
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
			device.AddPassword(model.PasswordEntry{
				Type: "enable-password",
				Hash: device.General.EnablePassword,
			})
		}
	case "interface":
		iface := p.parseInterface(tokens, lines, idx)
		device.AddInterface(iface)
	case "router":
		p.processRouter(device, tokens, lines, idx)
	case "ip":
		p.processIP(device, tokens)
	case "access-list":
		// same as IOS
	case "line":
		// same as IOS
	case "snmp-server":
		// same as IOS
	case "logging":
		// same as IOS
	case "banner":
		if len(tokens) > 1 {
			device.General.Banner = strings.Join(tokens[1:], " ")
		}
	case "ntp":
		// same as IOS
	case "username":
		// same as IOS
	case "aaa":
		// same as IOS
	case "platform":
		if strings.Contains(line, "model") || strings.Contains(line, "Model") {
			device.Model = strings.TrimPrefix(line, "platform ")
		}
	case "license":
		// license info
	case "service":
		// same as IOS
	}
}

func (p *IOSXEParser) parseInterface(tokens []string, lines []string, idx *int) model.Interface {
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
			}
		case "shutdown":
			iface.State = "shutdown"
		}
	}

	return iface
}

func (p *IOSXEParser) processRouter(device *model.DeviceConfig, tokens []string, lines []string, idx *int) {
	// IOS-XE uses the same routing protocol syntax as IOS
	// Delegate to a shared function
	if len(tokens) < 2 {
		return
	}
	switch tokens[1] {
	case "ospf":
		ospf := &model.OSPFConfig{ProcessID: 1}
		if len(tokens) > 2 {
			ospf.ProcessID, _ = parseAtoi(tokens[2])
		}
		device.Routing.OSPF = ospf
	case "bgp":
		bgp := &model.BGPConfig{}
		if len(tokens) > 2 {
			bgp.ASN, _ = parseAtoi(tokens[2])
		}
		device.Routing.BGP = bgp
	}
}

func (p *IOSXEParser) processIP(device *model.DeviceConfig, tokens []string) {
	if len(tokens) < 2 {
		return
	}
	switch tokens[1] {
	case "domain":
		if len(tokens) > 2 && tokens[2] == "lookup" {
			device.General.IPDomainLookup = true
		}
	case "name-server":
		if len(tokens) > 2 {
			device.DNS.Servers = append(device.DNS.Servers, tokens[2])
		}
	case "route":
		// static route
	}
}

func parseAtoi(s string) (int, error) {
	val := 0
	for _, c := range s {
		if c >= '0' && c <= '9' {
			val = val*10 + int(c-'0')
		} else {
			break
		}
	}
	return val, nil
}
