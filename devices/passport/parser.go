package passport

import (
	"bufio"
	"io"
	"strings"
	"time"

	"github.com/Cazo-Net/Netipe/internal/model"
	"github.com/Cazo-Net/Netipe/internal/parser"
)

func init() {
	parser.Register("passport", &PassportParser{})
}

type PassportParser struct{}

func (p *PassportParser) Name() string {
	return "Nortel Passport Parser"
}

func (p *PassportParser) SupportedTypes() []model.DeviceType {
	return []model.DeviceType{model.DevicePassport}
}

func (p *PassportParser) Detect(data []byte) bool {
	content := string(data)
	signatures := []string{
		"set switch",
		"set snmp",
		"set filter",
		"set port",
		"set vlan",
		"set ip",
		"Passport",
		"BayStack",
		"set logging",
		"enable snmp",
		"disable snmp",
	}
	matches := 0
	for _, sig := range signatures {
		if strings.Contains(content, sig) {
			matches++
		}
	}
	return matches >= 3
}

func (p *PassportParser) DetectScore(data []byte) int {
	content := string(data)
	signatures := []string{
		"set switch",
		"set snmp",
		"set filter",
		"set port",
		"set vlan",
		"set ip",
		"Passport",
		"BayStack",
		"set logging",
		"enable snmp",
		"disable snmp",
	}
	score := 0
	for _, sig := range signatures {
		if strings.Contains(content, sig) {
			score++
		}
	}
	return score
}

func (p *PassportParser) Parse(r io.Reader, deviceType model.DeviceType) (*model.DeviceConfig, error) {
	device := &model.DeviceConfig{
		DeviceType: model.DevicePassport,
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
		p.processLine(device, line)
	}

	device.SetDefaults()
	return device, nil
}

func (p *PassportParser) processLine(device *model.DeviceConfig, line string) {
	tokens := strings.Fields(line)
	if len(tokens) < 2 {
		return
	}

	switch tokens[0] {
	case "set":
		p.processSet(device, tokens)
	case "enable":
		if len(tokens) > 1 {
			switch tokens[1] {
			case "snmp":
				device.SNMP.Version = 2
			case "ssh":
				device.SSH.Enabled = true
			case "telnet":
				device.Telnet.Enabled = true
			}
		}
	case "disable":
		if len(tokens) > 1 {
			switch tokens[1] {
			case "snmp":
				device.SNMP.Version = 0
			case "ssh":
				device.SSH.Enabled = false
			case "telnet":
				device.Telnet.Enabled = false
			}
		}
	}
}

func (p *PassportParser) processSet(device *model.DeviceConfig, tokens []string) {
	if len(tokens) < 3 {
		return
	}

	switch tokens[1] {
	case "switch":
		if len(tokens) > 3 && tokens[2] == "name" {
			device.Hostname = tokens[3]
			device.General.Hostname = tokens[3]
			device.DeviceName = tokens[3]
		}
	case "snmp":
		p.processSNMP(device, tokens)
	case "filter":
		// filter definition
	case "port":
		// port config
	case "vlan":
		// VLAN config
	case "ip":
		if len(tokens) > 3 && tokens[2] == "route" {
			// static route
		}
	case "logging":
		device.Logging.Enabled = true
	}
}

func (p *PassportParser) processSNMP(device *model.DeviceConfig, tokens []string) {
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
