package nmp

import (
	"bufio"
	"io"
	"strings"
	"time"

	"github.com/netpipe/netpipe/internal/model"
	"github.com/netpipe/netpipe/internal/parser"
)

func init() {
	parser.Register("nmp", &NMPParser{})
}

type NMPParser struct{}

func (p *NMPParser) Name() string {
	return "Cisco NMP/CatOS Parser"
}

func (p *NMPParser) SupportedTypes() []model.DeviceType {
	return []model.DeviceType{model.DeviceNMP, model.DeviceCatOS}
}

func (p *NMPParser) Detect(data []byte) bool {
	content := string(data)
	signatures := []string{
		"set prompt",
		"set interface",
		"set snmp",
		"set password",
		"set enable",
		"set vlan",
		"set spantree",
		"set cdp",
		"set port",
		"set module",
		"show mod",
		"CatOS",
		"catalyst",
		"set test",
		"clear test",
	}
	matches := 0
	for _, sig := range signatures {
		if strings.Contains(content, sig) {
			matches++
		}
	}
	return matches >= 3
}

func (p *NMPParser) DetectScore(data []byte) int {
	content := string(data)
	signatures := []string{
		"set prompt",
		"set interface",
		"set snmp",
		"set password",
		"set enable",
		"set vlan",
		"set spantree",
		"set cdp",
		"set port",
		"set module",
		"show mod",
		"CatOS",
		"catalyst",
		"set test",
		"clear test",
	}
	score := 0
	for _, sig := range signatures {
		if strings.Contains(content, sig) {
			score++
		}
	}
	return score
}

func (p *NMPParser) Parse(r io.Reader, deviceType model.DeviceType) (*model.DeviceConfig, error) {
	device := &model.DeviceConfig{
		DeviceType: model.DeviceNMP,
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
		p.processLine(device, line)
	}

	device.SetDefaults()
	return device, nil
}

func (p *NMPParser) processLine(device *model.DeviceConfig, line string) {
	tokens := strings.Fields(line)
	if len(tokens) < 2 {
		return
	}

	if tokens[0] == "set" || tokens[0] == "clear" {
		p.processSet(device, tokens)
	}
}

func (p *NMPParser) processSet(device *model.DeviceConfig, tokens []string) {
	if len(tokens) < 3 {
		return
	}

	switch tokens[1] {
	case "prompt":
		device.Hostname = strings.Trim(tokens[2], "%")
		device.General.Hostname = device.Hostname
		device.DeviceName = device.Hostname
	case "password":
		device.AddPassword(model.PasswordEntry{
			Type: "line-console",
			Hash: tokens[2],
		})
	case "enable":
		if len(tokens) > 2 && tokens[2] == "password" && len(tokens) > 3 {
			device.General.EnablePassword = tokens[3]
			device.AddPassword(model.PasswordEntry{
				Type: "enable-password",
				Hash: tokens[3],
			})
		}
	case "snmp":
		p.processSNMP(device, tokens)
	case "interface":
		p.processInterface(device, tokens)
	case "vlan":
		// VLAN config
	case "spantree":
		// spanning tree
	case "cdp":
		if len(tokens) > 2 && tokens[2] == "enable" {
			device.General.CDPEnabled = true
		}
	case "port":
		// port config
	case "module":
		// module config
	case "test":
		// test config
	}
}

func (p *NMPParser) processSNMP(device *model.DeviceConfig, tokens []string) {
	if len(tokens) < 4 {
		return
	}

	switch tokens[2] {
	case "community":
		if len(tokens) > 3 {
			device.SNMP.Community = tokens[3]
			device.SNMP.Version = 2
		}
	case "trap":
		if len(tokens) > 3 {
			device.SNMP.TrapServers = append(device.SNMP.TrapServers, tokens[3])
		}
	}
}

func (p *NMPParser) processInterface(device *model.DeviceConfig, tokens []string) {
	if len(tokens) < 4 {
		return
	}

	iface := model.Interface{
		Name: tokens[2],
	}

	for i := 3; i < len(tokens)-1; i += 2 {
		switch tokens[i] {
		case "name":
			iface.Description = tokens[i+1]
		}
	}

	device.AddInterface(iface)
}
