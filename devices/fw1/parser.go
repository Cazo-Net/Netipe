package fw1

import (
	"bufio"
	"io"
	"strings"
	"time"

	"github.com/Cazo-Net/Netipe/internal/model"
	"github.com/Cazo-Net/Netipe/internal/parser"
)

func init() {
	parser.Register("fw1", &FW1Parser{})
}

type FW1Parser struct{}

func (p *FW1Parser) Name() string {
	return "CheckPoint Firewall-1 Parser"
}

func (p *FW1Parser) SupportedTypes() []model.DeviceType {
	return []model.DeviceType{model.DeviceFW1}
}

func (p *FW1Parser) Detect(data []byte) bool {
	content := string(data)
	signatures := []string{
		":config",
		":tables",
		":filter",
		":rule",
		":service",
		":network",
		":host",
		"FW-1",
		"CheckPoint",
		"firewall-1",
		"cp:",
		"(conf",
		"(top",
	}
	matches := 0
	for _, sig := range signatures {
		if strings.Contains(content, sig) {
			matches++
		}
	}
	return matches >= 2
}

func (p *FW1Parser) DetectScore(data []byte) int {
	content := string(data)
	signatures := []string{
		":config",
		":tables",
		":filter",
		":rule",
		":service",
		":network",
		":host",
		"FW-1",
		"CheckPoint",
		"firewall-1",
		"cp:",
		"(conf",
		"(top",
	}
	score := 0
	for _, sig := range signatures {
		if strings.Contains(content, sig) {
			score++
		}
	}
	return score
}

func (p *FW1Parser) Parse(r io.Reader, deviceType model.DeviceType) (*model.DeviceConfig, error) {
	device := &model.DeviceConfig{
		DeviceType: model.DeviceFW1,
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
		p.processLine(device, line, lines, &i)
	}

	device.SetDefaults()
	return device, nil
}

func (p *FW1Parser) processLine(device *model.DeviceConfig, line string, lines []string, idx *int) {
	tokens := strings.Fields(line)
	if len(tokens) == 0 {
		return
	}

	if strings.HasPrefix(line, ":") {
		p.processConfLine(device, tokens)
		return
	}

	if strings.HasPrefix(line, "(") {
		p.processSEXPLine(device, line, tokens)
		return
	}
}

func (p *FW1Parser) processConfLine(device *model.DeviceConfig, tokens []string) {
	if len(tokens) < 2 {
		return
	}

	switch tokens[0] {
	case ":hostname":
		device.Hostname = tokens[1]
		device.General.Hostname = tokens[1]
		device.DeviceName = tokens[1]
	case ":snmp":
		if len(tokens) > 2 {
			device.SNMP.Community = tokens[2]
			device.SNMP.Version = 2
		}
	case ":telnet":
		device.Telnet.Enabled = true
	case ":ssh":
		device.SSH.Enabled = true
	}
}

func (p *FW1Parser) processSEXPLine(device *model.DeviceConfig, line string, tokens []string) {
	if strings.Contains(line, ":rule") {
		acl := model.ACL{
			Type: "fw1-rule",
		}
		device.AddACL(acl)
	} else if strings.Contains(line, ":service") {
		// service definition
	} else if strings.Contains(line, ":network") {
		// network object definition
	} else if strings.Contains(line, ":host") {
		// host object definition
	}
}
