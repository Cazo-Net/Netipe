package bigip

import (
	"bufio"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/Cazo-Net/Netipe/internal/model"
	"github.com/Cazo-Net/Netipe/internal/parser"
)

func init() {
	parser.Register("bigip", &BIGIPParser{})
}

type BIGIPParser struct{}

func (p *BIGIPParser) Name() string {
	return "F5 BIG-IP Parser"
}

func (p *BIGIPParser) SupportedTypes() []model.DeviceType {
	return []model.DeviceType{model.DeviceBIGIP}
}

func (p *BIGIPParser) Detect(data []byte) bool {
	content := string(data)
	signatures := []string{
		"cm config sync",
		"ltm virtual",
		"ltm pool",
		"ltm node",
		"ltm monitor",
		"ltm persistence",
		"sys global-settings",
		"sys httpd",
		"sys sshd",
		"sys ntp",
		"sys dns",
		"sys snmp",
		"sys management-ip",
		"auth radius",
		"auth tacacs",
		"net route",
		"net self",
		"net vlan",
		"tmsh",
		"BIG-IP",
		"f5.com",
	}
	matches := 0
	for _, sig := range signatures {
		if strings.Contains(content, sig) {
			matches++
		}
	}
	return matches >= 3
}

func (p *BIGIPParser) DetectScore(data []byte) int {
	content := string(data)
	signatures := []string{
		"cm config sync",
		"ltm virtual",
		"ltm pool",
		"ltm node",
		"ltm monitor",
		"ltm persistence",
		"sys global-settings",
		"sys httpd",
		"sys sshd",
		"sys ntp",
		"sys dns",
		"sys snmp",
		"sys management-ip",
		"auth radius",
		"auth tacacs",
		"net route",
		"net self",
		"net vlan",
		"tmsh",
		"BIG-IP",
		"f5.com",
	}
	score := 0
	for _, sig := range signatures {
		if strings.Contains(content, sig) {
			score++
		}
	}
	return score
}

func (p *BIGIPParser) Parse(r io.Reader, deviceType model.DeviceType) (*model.DeviceConfig, error) {
	device := &model.DeviceConfig{
		DeviceType: model.DeviceBIGIP,
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

func (p *BIGIPParser) processLine(device *model.DeviceConfig, line string, lines []string, idx *int) {
	tokens := strings.Fields(line)
	if len(tokens) == 0 {
		return
	}

	if strings.HasPrefix(line, "modify ") || strings.HasPrefix(line, "create ") {
		p.processCommand(device, tokens[1:])
		return
	}

	switch tokens[0] {
	case "sys":
		p.processSys(device, tokens, lines, idx)
	case "ltm":
		p.processLTM(device, tokens, lines, idx)
	case "net":
		p.processNet(device, tokens, lines, idx)
	case "auth":
		p.processAuth(device, tokens)
	}
}

func (p *BIGIPParser) processCommand(device *model.DeviceConfig, tokens []string) {
	if len(tokens) < 2 {
		return
	}

	switch tokens[0] {
	case "sys":
		p.processSys(device, tokens, nil, nil)
	case "ltm":
		p.processLTM(device, tokens, nil, nil)
	case "net":
		p.processNet(device, tokens, nil, nil)
	}
}

func (p *BIGIPParser) processSys(device *model.DeviceConfig, tokens []string, lines []string, idx *int) {
	if len(tokens) < 2 {
		return
	}

	switch tokens[1] {
	case "global-settings":
		for i := 2; i < len(tokens)-1; i += 2 {
			switch tokens[i] {
			case "hostname":
				device.Hostname = tokens[i+1]
				device.General.Hostname = tokens[i+1]
				device.DeviceName = tokens[i+1]
			case "gui-setup":
				// GUI setup
			}
		}
	case "httpd":
		device.General.HTTPServer = true
		for i := 2; i < len(tokens)-1; i += 2 {
			switch tokens[i] {
			case "ssl-port":
				device.HTTP.Port, _ = strconv.Atoi(tokens[i+1])
				device.HTTP.SSL = true
			case "server-ssl":
				device.HTTP.SSL = true
			}
		}
	case "sshd":
		device.SSH.Enabled = true
		for i := 2; i < len(tokens)-1; i += 2 {
			switch tokens[i] {
			case "port":
				device.SSH.Port, _ = strconv.Atoi(tokens[i+1])
			case "inactivity-timeout":
				timeout, _ := strconv.Atoi(tokens[i+1])
				device.SSH.Timeout = time.Duration(timeout) * time.Second
			}
		}
	case "ntp":
		for i := 2; i < len(tokens)-1; i += 2 {
			switch tokens[i] {
			case "servers":
				device.NTP.Servers = append(device.NTP.Servers, model.NTPServer{
					Address: tokens[i+1],
					Version: 4,
				})
			}
		}
	case "dns":
		for i := 2; i < len(tokens)-1; i += 2 {
			switch tokens[i] {
			case "servers":
				device.DNS.Servers = append(device.DNS.Servers, tokens[i+1])
			case "name-servers":
				device.DNS.NameServers = append(device.DNS.NameServers, net.ParseIP(tokens[i+1]))
			}
		}
	case "snmp":
		for i := 2; i < len(tokens)-1; i += 2 {
			switch tokens[i] {
			case "contact":
				device.SNMP.Contact = strings.Trim(tokens[i+1], "\"")
			case "location":
				device.SNMP.Location = strings.Trim(tokens[i+1], "\"")
			}
		}
	case "management-ip":
		if len(tokens) > 2 {
			iface := model.Interface{
				Name: "management",
				CIDR: tokens[2],
			}
			device.AddInterface(iface)
		}
	}
}

func (p *BIGIPParser) processLTM(device *model.DeviceConfig, tokens []string, lines []string, idx *int) {
	// LTM (Local Traffic Manager) configuration
	// Virtual servers, pools, nodes, monitors
	if len(tokens) < 2 {
		return
	}

	switch tokens[1] {
	case "virtual":
		// Virtual server config
	case "pool":
		// Pool config
	case "node":
		// Node config
	case "monitor":
		// Monitor config
	case "persistence":
		// Persistence profile config
	case "profile":
		// Profile config
	case "rule":
		// iRule config
	case "data-group":
		// Data group config
	case "snatpool":
		// SNAT pool config
	case "snat":
		// SNAT config
	case "nat":
		// NAT config
	}
}

func (p *BIGIPParser) processNet(device *model.DeviceConfig, tokens []string, lines []string, idx *int) {
	if len(tokens) < 2 {
		return
	}

	switch tokens[1] {
	case "route":
		// Route configuration
	case "self":
		// Self IP configuration
	case "vlan":
		// VLAN configuration
	case "interface":
		// Interface configuration
	}
}

func (p *BIGIPParser) processAuth(device *model.DeviceConfig, tokens []string) {
	if len(tokens) < 2 {
		return
	}

	switch tokens[1] {
	case "radius":
		device.AAA.RadServer = "radius"
	case "tacacs":
		device.AAA.TacacsServer = "tacacs"
	}
}


