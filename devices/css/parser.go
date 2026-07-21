package css

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
	parser.Register("css", &CSSParser{})
}

type CSSParser struct{}

func (p *CSSParser) Name() string {
	return "Cisco CSS Parser"
}

func (p *CSSParser) SupportedTypes() []model.DeviceType {
	return []model.DeviceType{model.DeviceCSS}
}

func (p *CSSParser) Detect(data []byte) bool {
	content := string(data)
	signatures := []string{
		"set prompt",
		"interface",
		"service",
		"owner",
		"content",
		"group",
		"keepalive",
		"acl",
		"snmp",
		"ssh",
		"telnet",
		"circuit",
		"ip address",
		"css",
	}
	matches := 0
	for _, sig := range signatures {
		if strings.Contains(content, sig) {
			matches++
		}
	}
	return matches >= 3
}

func (p *CSSParser) DetectScore(data []byte) int {
	content := string(data)
	signatures := []string{
		"set prompt",
		"interface",
		"service",
		"owner",
		"content",
		"group",
		"keepalive",
		"acl",
		"snmp",
		"ssh",
		"telnet",
		"circuit",
		"ip address",
		"css",
	}
	score := 0
	for _, sig := range signatures {
		if strings.Contains(content, sig) {
			score++
		}
	}
	return score
}

func (p *CSSParser) Parse(r io.Reader, deviceType model.DeviceType) (*model.DeviceConfig, error) {
	device := &model.DeviceConfig{
		DeviceType: model.DeviceCSS,
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

func (p *CSSParser) processLine(device *model.DeviceConfig, line string, lines []string, idx *int) {
	tokens := strings.Fields(line)
	if len(tokens) == 0 {
		return
	}

	switch tokens[0] {
	case "set":
		p.processSet(device, tokens)
	case "interface":
		p.processInterface(device, tokens, lines, idx)
	case "service":
		// service definition
	case "group":
		// group definition
	case "content":
		// content rule
	case "owner":
		// owner definition
	case "acl":
		// ACL definition
	case "circuit":
		// circuit definition
	}
}

func (p *CSSParser) processSet(device *model.DeviceConfig, tokens []string) {
	if len(tokens) < 3 {
		return
	}

	switch tokens[1] {
	case "prompt":
		device.Hostname = strings.Trim(tokens[2], "%")
		device.General.Hostname = device.Hostname
		device.DeviceName = device.Hostname
	case "ssh":
		device.SSH.Enabled = true
	case "snmp":
		if len(tokens) > 3 && tokens[2] == "community" {
			device.SNMP.Community = tokens[3]
			device.SNMP.Version = 2
		}
	case "telnet":
		device.Telnet.Enabled = true
	case "ip":
		if len(tokens) > 3 && tokens[2] == "route" {
			// static route
		}
	}
}

func (p *CSSParser) processInterface(device *model.DeviceConfig, tokens []string, lines []string, idx *int) {
	if len(tokens) < 2 {
		return
	}

	iface := model.Interface{
		Name: tokens[1],
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
		case "ip":
			if len(tokens) > 1 && tokens[1] == "address" && len(tokens) > 2 {
				iface.CIDR = tokens[2]
			}
		case "vlan":
			if len(tokens) > 1 {
				iface.VLAN, _ = strconv.Atoi(tokens[1])
			}
		}
	}

	device.AddInterface(iface)
}
