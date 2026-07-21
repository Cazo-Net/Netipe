package pixasa

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
	parser.Register("pixasa", &PIXASAParser{})
}

type PIXASAParser struct{}

func (p *PIXASAParser) Name() string {
	return "Cisco PIX/ASA Parser"
}

func (p *PIXASAParser) SupportedTypes() []model.DeviceType {
	return []model.DeviceType{
		model.DevicePIX,
		model.DeviceASA,
		model.DeviceFWSM,
	}
}

func (p *PIXASAParser) Detect(data []byte) bool {
	content := string(data)
	signatures := []string{
		": Saved",
		": Written by",
		"enable password",
		"passwd",
		"access-list",
		"interface Ethernet",
		"interface GigabitEthernet",
		"object-group",
		"timeout",
		"fixup protocol",
		"global (",
		"nat (",
		"static (",
		"route ",
		"security-level",
		"shutdown",
		"class-map",
		"policy-map",
		"service-policy",
		"telnet",
		"ssh",
		"logging",
		"snmp-server",
		"aaa-server",
		"timeout xlate",
		"timeout conn",
		"timeout syslog",
		"ip address",
		"nameif",
	}
	matches := 0
	for _, sig := range signatures {
		if strings.Contains(content, sig) {
			matches++
		}
	}
	return matches >= 3
}

func (p *PIXASAParser) DetectScore(data []byte) int {
	content := string(data)
	signatures := []string{
		": Saved",
		": Written by",
		"enable password",
		"passwd",
		"access-list",
		"interface Ethernet",
		"interface GigabitEthernet",
		"object-group",
		"timeout",
		"fixup protocol",
		"global (",
		"nat (",
		"static (",
		"route ",
		"security-level",
		"shutdown",
		"class-map",
		"policy-map",
		"service-policy",
		"telnet",
		"ssh",
		"logging",
		"snmp-server",
		"aaa-server",
		"timeout xlate",
		"timeout conn",
		"timeout syslog",
		"ip address",
		"nameif",
	}
	score := 0
	for _, sig := range signatures {
		if strings.Contains(content, sig) {
			score++
		}
	}
	return score
}

func (p *PIXASAParser) Parse(r io.Reader, deviceType model.DeviceType) (*model.DeviceConfig, error) {
	device := &model.DeviceConfig{
		DeviceType: deviceType,
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
		if line == "" || strings.HasPrefix(line, ":") || strings.HasPrefix(line, "!") || strings.HasPrefix(line, "#") {
			continue
		}
		p.processLine(device, line, lines, &i)
	}

	device.SetDefaults()
	return device, nil
}

func (p *PIXASAParser) processLine(device *model.DeviceConfig, line string, lines []string, idx *int) {
	tokens := strings.Fields(line)
	if len(tokens) == 0 {
		return
	}

	switch tokens[0] {
	case "hostname":
		if len(tokens) > 1 {
			device.Hostname = tokens[1]
			device.General.Hostname = tokens[1]
			if device.DeviceName == "" {
				device.DeviceName = tokens[1]
			}
		}
	case "enable":
		if len(tokens) > 1 && tokens[1] == "password" {
			device.General.EnablePassword = strings.Join(tokens[2:], " ")
			device.AddPassword(model.PasswordEntry{
				Type: "enable-password",
				Hash: device.General.EnablePassword,
			})
		}
	case "passwd":
		if len(tokens) > 1 {
			device.General.ServicePassword = tokens[1]
			device.AddPassword(model.PasswordEntry{
				Type: "passwd",
				Hash: tokens[1],
			})
		}
	case "interface":
		p.processInterface(device, tokens, lines, idx)
	case "access-list":
		p.processAccessList(device, tokens)
	case "global":
		p.processGlobal(device, tokens)
	case "nat":
		p.processNAT(device, tokens)
	case "static":
		p.processStaticNAT(device, tokens)
	case "route":
		p.processRoute(device, tokens)
	case "timeout":
		p.processTimeout(device, tokens)
	case "telnet":
		p.processTelnet(device, tokens)
	case "ssh":
		p.processSSH(device, tokens)
	case "logging":
		p.processLogging(device, tokens)
	case "snmp-server":
		p.processSNMP(device, tokens)
	case "aaa-server":
		p.processAAA(device, tokens)
	case "http":
		p.processHTTP(device, tokens)
	case "object-group":
		// object-group
	case "class-map":
		// class-map
	case "policy-map":
		// policy-map
	case "service-policy":
		// service-policy
	case "crypto":
		// crypto config
	case "isakmp":
		// IKE config
	case "nat-control":
		// NAT control
	case "names":
		// name mappings
	case "name":
		if len(tokens) > 2 {
			// name resolution
		}
	}
}

func (p *PIXASAParser) processInterface(device *model.DeviceConfig, tokens []string, lines []string, idx *int) {
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
		case "nameif":
			if len(tokens) > 1 {
				iface.Zone = tokens[1]
			}
		case "security-level":
			if len(tokens) > 1 {
				iface.SecurityLevel, _ = strconv.Atoi(tokens[1])
			}
		case "ip":
			if len(tokens) > 1 && tokens[1] == "address" {
				if len(tokens) > 2 {
					iface.CIDR = tokens[2]
				}
			}
		case "vlan":
			if len(tokens) > 1 {
				iface.VLAN, _ = strconv.Atoi(tokens[1])
			}
		case "description":
			if len(tokens) > 1 {
				iface.Description = strings.Join(tokens[1:], " ")
			}
		case "access-group":
			if len(tokens) > 2 {
				iface.ACLName = tokens[2]
			}
		case "no":
			if len(tokens) > 1 && tokens[1] == "shutdown" {
				iface.State = "up"
			}
		case "shutdown":
			iface.State = "shutdown"
		}
	}

	device.AddInterface(iface)
}

func (p *PIXASAParser) processAccessList(device *model.DeviceConfig, tokens []string) {
	if len(tokens) < 2 {
		return
	}

	aclName := tokens[1]

	acl := model.ACL{
		Name: aclName,
		Type: "extended",
	}

	rule := model.ACLRule{
		Action:  "permit",
		Enabled: true,
	}

	currentACL := device.FindACL(aclName)
	if currentACL == nil {
		device.AddACL(acl)
		currentACL = device.FindACL(aclName)
	}

	if len(tokens) > 2 {
		if tokens[2] == "deny" {
			rule.Action = "deny"
		}
	}

	startIdx := 3
	if len(tokens) > startIdx {
		rule.Protocol = tokens[startIdx]
		startIdx++
	}
	if len(tokens) > startIdx {
		rule.Source = tokens[startIdx]
		startIdx++
	}
	if len(tokens) > startIdx {
		rule.SourcePort = tokens[startIdx]
		startIdx++
	}
	if len(tokens) > startIdx {
		rule.Destination = tokens[startIdx]
		startIdx++
	}
	if len(tokens) > startIdx {
		rule.DestPort = tokens[startIdx]
	}

	if strings.Contains(lineStr(tokens), "log") {
		rule.Log = true
	}

	if strings.Contains(lineStr(tokens), "eq") {
		// handle eq ports
	}

	currentACL.AddRule(rule)
}

func (p *PIXASAParser) processGlobal(device *model.DeviceConfig, tokens []string) {
	// global (outside) 1 interface
}

func (p *PIXASAParser) processNAT(device *model.DeviceConfig, tokens []string) {
	// nat (inside) 1 0.0.0.0 0.0.0.0
}

func (p *PIXASAParser) processStaticNAT(device *model.DeviceConfig, tokens []string) {
	// static (inside,outside) 192.168.1.1 10.0.0.1
}

func (p *PIXASAParser) processRoute(device *model.DeviceConfig, tokens []string) {
	// route outside 0.0.0.0 0.0.0.0 192.168.1.1
}

func (p *PIXASAParser) processTimeout(device *model.DeviceConfig, tokens []string) {
	if len(tokens) < 3 {
		return
	}

	timeoutName := tokens[1]
	timeoutVal, _ := strconv.Atoi(tokens[2])

	_ = timeoutName
	_ = timeoutVal
}

func (p *PIXASAParser) processTelnet(device *model.DeviceConfig, tokens []string) {
	device.Telnet.Enabled = true
	if len(tokens) > 1 && tokens[1] == "0.0.0.0" {
		// telnet 0.0.0.0 0.0.0.0 inside
	}
}

func (p *PIXASAParser) processSSH(device *model.DeviceConfig, tokens []string) {
	device.SSH.Enabled = true
	if len(tokens) > 2 {
		if tokens[1] == "0.0.0.0" || tokens[1] == "::" {
			// SSH access
		}
	}
}

func (p *PIXASAParser) processLogging(device *model.DeviceConfig, tokens []string) {
	if len(tokens) < 2 {
		return
	}

	device.Logging.Enabled = true

	switch tokens[1] {
	case "buffer":
		if len(tokens) > 2 {
			device.Logging.BufferSize, _ = strconv.Atoi(tokens[2])
		}
	case "host":
		if len(tokens) > 2 {
			device.Logging.SyslogServers = append(device.Logging.SyslogServers, tokens[2])
		}
	case "trap":
		if len(tokens) > 2 {
			device.Logging.TrapLevel, _ = strconv.Atoi(tokens[2])
		}
	case "enable":
		if len(tokens) > 2 {
			device.Logging.ConsoleLevel, _ = strconv.Atoi(tokens[2])
		}
	case "timestamp":
		device.Logging.Timestamps = true
	}
}

func (p *PIXASAParser) processSNMP(device *model.DeviceConfig, tokens []string) {
	if len(tokens) < 2 {
		return
	}

	switch tokens[1] {
	case "community":
		if len(tokens) > 2 {
			device.SNMP.Community = tokens[2]
			if device.SNMP.Version == 0 {
				device.SNMP.Version = 2
			}
		}
	case "host":
		if len(tokens) > 2 {
			device.SNMP.TrapServers = append(device.SNMP.TrapServers, tokens[2])
		}
	case "contact":
		if len(tokens) > 2 {
			device.SNMP.Contact = strings.Join(tokens[2:], " ")
		}
	case "location":
		if len(tokens) > 2 {
			device.SNMP.Location = strings.Join(tokens[2:], " ")
		}
	case "version":
		if len(tokens) > 2 {
			switch tokens[2] {
			case "1":
				device.SNMP.Version = 1
			case "2c":
				device.SNMP.Version = 2
			}
		}
	case "interface":
		if len(tokens) > 2 {
			device.SNMP.ACLName = tokens[2]
		}
	}
}

func (p *PIXASAParser) processAAA(device *model.DeviceConfig, tokens []string) {
	if len(tokens) < 2 {
		return
	}

	if tokens[1] == "server" {
		// aaa-server TACACS+ protocol tacacs+
		if len(tokens) > 3 && tokens[3] == "protocol" {
			if len(tokens) > 4 {
				switch strings.ToLower(tokens[4]) {
				case "tacacs+":
					device.AAA.TacacsServer = tokens[2]
				case "radius":
					device.AAA.RadServer = tokens[2]
				}
			}
		}
	}
}

func (p *PIXASAParser) processHTTP(device *model.DeviceConfig, tokens []string) {
	if len(tokens) > 1 {
		switch tokens[1] {
		case "server":
			device.General.HTTPServer = true
		case "enable":
			device.General.HTTPServer = true
		}
	}
}

func lineStr(tokens []string) string {
	return strings.Join(tokens, " ")
}
