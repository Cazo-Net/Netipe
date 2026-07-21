package ios

import (
	"bufio"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/Cazo-Net/Netipe/internal/model"
	"github.com/Cazo-Net/Netipe/internal/parser"
	"github.com/Cazo-Net/Netipe/internal/util"
)

func init() {
	parser.Register("ios", &IOSParser{})
}

type IOSParser struct{}

func (p *IOSParser) Name() string {
	return "Cisco IOS Parser"
}

func (p *IOSParser) SupportedTypes() []model.DeviceType {
	return []model.DeviceType{
		model.DeviceIOSRouter,
		model.DeviceIOSSwitch,
		model.DeviceIOSCatalyst,
	}
}

func (p *IOSParser) Detect(data []byte) bool {
	content := string(data)
	signatures := []string{
		"service timestamps debug datetime msec",
		"service timestamps log datetime msec",
		"service password-encryption",
		"no service pad",
		"enable secret",
		"enable password",
		"interface GigabitEthernet",
		"interface FastEthernet",
		"interface Serial",
		"router ospf",
		"router bgp",
		"router eigrp",
		"access-list",
		"ip access-list",
		"line vty",
		"line con 0",
		"banner motd",
		"clock timezone",
		"ntp server",
		"snmp-server community",
		"logging buffered",
		"spanning-tree",
		"no ip source-route",
		"ip route ",
		"version 12",
		"version 15",
		"service config",
		"boot system",
		"boot-start-marker",
	}
	uniqueIosSignatures := []string{
		"service password-encryption",
		"line vty",
		"no service pad",
		"enable secret",
		"banner motd",
		"service timestamps debug datetime msec",
		"service timestamps log datetime msec",
	}
	matches := 0
	for _, sig := range signatures {
		if strings.Contains(content, sig) {
			matches++
		}
	}
	uniqueMatches := 0
	for _, sig := range uniqueIosSignatures {
		if strings.Contains(content, sig) {
			uniqueMatches++
		}
	}
	return matches >= 3 && uniqueMatches >= 2
}

func (p *IOSParser) DetectScore(data []byte) int {
	content := string(data)
	signatures := []string{
		"service timestamps debug datetime msec",
		"service timestamps log datetime msec",
		"service password-encryption",
		"no service pad",
		"enable secret",
		"enable password",
		"interface GigabitEthernet",
		"interface FastEthernet",
		"interface Serial",
		"router ospf",
		"router bgp",
		"router eigrp",
		"access-list",
		"ip access-list",
		"line vty",
		"line con 0",
		"banner motd",
		"clock timezone",
		"ntp server",
		"snmp-server community",
		"logging buffered",
		"spanning-tree",
		"no ip source-route",
		"ip route ",
		"version 12",
		"version 15",
		"service config",
		"boot system",
		"boot-start-marker",
	}
	uniqueIosSignatures := []string{
		"service password-encryption",
		"line vty",
		"no service pad",
		"enable secret",
		"banner motd",
		"service timestamps debug datetime msec",
		"service timestamps log datetime msec",
	}
	score := 0
	for _, sig := range signatures {
		if strings.Contains(content, sig) {
			score++
		}
	}
	for _, sig := range uniqueIosSignatures {
		if strings.Contains(content, sig) {
			score++
		}
	}
	return score
}

func (p *IOSParser) Parse(r io.Reader, deviceType model.DeviceType) (*model.DeviceConfig, error) {
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
		if line == "" || strings.HasPrefix(line, "!") {
			continue
		}
		p.processLine(device, line, lines, &i)
	}

	device.SetDefaults()
	return device, nil
}

func (p *IOSParser) processLine(device *model.DeviceConfig, line string, lines []string, idx *int) {
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
	case "service":
		p.processService(device, tokens)
	case "no":
		p.processNo(device, tokens)
	case "interface":
		iface := p.parseInterface(tokens, lines, idx)
		device.AddInterface(iface)
	case "ip":
		p.processIP(device, tokens, lines, idx)
	case "access-list":
		p.parseAccessList(device, tokens)
	case "ipx":
		p.parseIPXAccessList(device, tokens)
	case "line":
		p.processLineConfig(device, tokens, lines, idx)
	case "router":
		p.processRouter(device, tokens, lines, idx)
	case "snmp-server":
		p.processSNMP(device, tokens)
	case "logging":
		p.processLogging(device, tokens)
	case "banner":
		p.processBanner(device, tokens, lines, idx)
	case "ntp":
		p.processNTP(device, tokens)
	case "username":
		p.processUsername(device, tokens)
	case "aaa":
		p.processAAA(device, tokens)
	case "clock":
		p.processClock(device, tokens)
	case "spanning-tree":
		device.General.CDPEnabled = true
	case "cdp":
		if len(tokens) > 1 && tokens[1] == "run" {
			device.General.CDPEnabled = true
		}
	}
}

func (p *IOSParser) processService(device *model.DeviceConfig, tokens []string) {
	if len(tokens) < 2 {
		return
	}
	switch tokens[1] {
	case "password-encryption":
		device.General.ServicePasswordEnc = true
	case "timestamps":
		if len(tokens) > 2 {
			if tokens[2] == "debug" || tokens[2] == "log" {
				device.Logging.Timestamps = true
			}
		}
	case "encrypt":
		device.General.ServiceEncrypt = true
	case "password":
		if len(tokens) > 2 && tokens[2] == "encryption" {
			device.General.ServicePasswordEnc = true
		}
	}
}

func (p *IOSParser) processNo(device *model.DeviceConfig, tokens []string) {
	if len(tokens) < 2 {
		return
	}
	switch tokens[1] {
	case "service":
		if len(tokens) > 2 {
			switch tokens[2] {
			case "pad":
				device.General.Pad = false
			case "finger":
				device.General.Finger = false
			}
		}
	case "ip":
		if len(tokens) > 2 {
			switch tokens[2] {
			case "source-route":
				device.General.IPSourceRouting = false
			case "proxy-arp":
				device.General.ProxyARP = false
			case "bootp":
				device.General.IPBootpServer = false
			}
		}
	case "cdp":
		device.General.CDPEnabled = false
	case "finger":
		device.General.Finger = false
	}
}

func (p *IOSParser) parseInterface(tokens []string, lines []string, idx *int) model.Interface {
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
			iface.Description = strings.TrimPrefix(strings.TrimPrefix(line, "description"), " ")
		case "ip":
			if len(tokens) > 1 {
				switch tokens[1] {
				case "address":
					if len(tokens) > 2 {
						ip, mask, err := util.ParseCIDR(tokens[2])
						if err == nil {
							iface.IPAddress = ip
							iface.SubnetMask = mask
							iface.CIDR = tokens[2]
						} else if len(tokens) > 3 {
							ip = net.ParseIP(tokens[2])
							mask = net.IPMask(net.ParseIP(tokens[3]).To4())
							if ip != nil {
								iface.IPAddress = ip
								iface.SubnetMask = mask
							}
						}
					}
				case "access-group":
					if len(tokens) > 2 {
						iface.ACLName = tokens[2]
					}
				case "proxy-arp":
					iface.ProxyARP = true
				}
			}
		case "switchport":
			iface.Switchport = true
			if len(tokens) > 1 {
				switch tokens[1] {
				case "access":
					if len(tokens) > 2 && tokens[2] == "vlan" && len(tokens) > 3 {
						iface.AccessVLAN, _ = strconv.Atoi(tokens[3])
					}
				case "trunk":
					if len(tokens) > 2 {
						switch tokens[2] {
						case "allowed":
							if len(tokens) > 3 && tokens[3] == "vlan" && len(tokens) > 4 {
								iface.TrunkVLANs = parseVLANList(tokens[4])
							}
						case "native":
							if len(tokens) > 2 && tokens[2] == "vlan" && len(tokens) > 3 {
								iface.AccessVLAN, _ = strconv.Atoi(tokens[3])
							}
						}
					}
				}
			}
		case "vlan":
			if len(tokens) > 1 {
				iface.VLAN, _ = strconv.Atoi(tokens[1])
			}
		case "cdp":
			if len(tokens) > 1 && tokens[1] == "enable" {
				iface.CDPEnabled = true
			} else if len(tokens) > 1 && tokens[1] == "disable" {
				iface.CDPEnabled = false
			}
		case "shutdown":
			iface.State = "shutdown"
		case "no":
			if len(tokens) > 1 {
				switch tokens[1] {
				case "shutdown":
					iface.State = "up"
				case "cdp":
					iface.CDPEnabled = false
				}
			}
		case "bandwidth":
			// informational
		case "delay":
			// informational
		case "standby":
			// HSRP config
		case "vrrp":
			// VRRP config
		}
	}

	return iface
}

func (p *IOSParser) processIP(device *model.DeviceConfig, tokens []string, lines []string, idx *int) {
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
			device.DNS.NameServers = append(device.DNS.NameServers, net.ParseIP(tokens[2]))
		}
	case "domain-name":
		if len(tokens) > 2 {
			device.DNS.DomainName = tokens[2]
		}
	case "source-route":
		device.General.IPSourceRouting = true
	case "proxy-arp":
		device.General.ProxyARP = true
	case "bootp":
		device.General.IPBootpServer = true
	case "route":
		// static route
	case "access-list":
		p.parseIPAccessList(device, tokens)
	case "class":
		// class-map / policy-map
	case "http":
		if len(tokens) > 2 {
			switch tokens[2] {
			case "server":
				device.General.HTTPServer = true
			case "secure-server":
				device.General.HTTPServer = true
				device.HTTP.SSL = true
			}
		}
	}
}

func (p *IOSParser) parseAccessList(device *model.DeviceConfig, tokens []string) {
	if len(tokens) < 2 {
		return
	}

	numStr := tokens[1]
	num, err := strconv.Atoi(numStr)
	if err != nil {
		return
	}

	acl := model.ACL{
		Name:   numStr,
		Number: num,
		Type:   "standard",
	}

	if num >= 100 && num <= 199 {
		acl.Type = "extended"
	} else if num >= 2000 && num <= 2699 {
		acl.Type = "extended"
	} else if num >= 1300 && num <= 1999 {
		acl.Type = "reflexive"
	} else if num >= 2000 && num <= 2699 {
		acl.Type = "extended"
	}

	rule := model.ACLRule{
		Action: "permit",
		Enabled: true,
	}

	if len(tokens) > 2 {
		if tokens[2] == "deny" {
			rule.Action = "deny"
		}
	}

	if len(tokens) > 3 {
		rule.Source = tokens[3]
		if rule.Source == "any" {
			rule.Source = "any"
		}
	}

	if acl.Type == "extended" && len(tokens) > 4 {
		rule.Protocol = tokens[4]
	}

	if len(tokens) > 5 {
		rule.Destination = tokens[5]
	}

	acl.AddRule(rule)
	device.AddACL(acl)
}

func (p *IOSParser) parseIPAccessList(device *model.DeviceConfig, tokens []string) {
	if len(tokens) < 4 {
		return
	}

	aclType := tokens[2]
	aclName := tokens[3]

	acl := model.ACL{
		Name:   aclName,
		Type:   aclType,
		Number: 0,
	}

	device.AddACL(acl)
}

func (p *IOSParser) parseIPXAccessList(device *model.DeviceConfig, tokens []string) {
	// IPX access lists - legacy
}

func (p *IOSParser) processLineConfig(device *model.DeviceConfig, tokens []string, lines []string, idx *int) {
	if len(tokens) < 2 {
		return
	}

	lineType := tokens[0]
	lineNum := 0
	if len(tokens) > 2 {
		lineNum, _ = strconv.Atoi(tokens[2])
	}

	_ = lineType
	_ = lineNum

	for i := *idx + 1; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" || !strings.HasPrefix(line, " ") {
			break
		}
		*idx = i
		line = strings.TrimSpace(line)
		ltokens := strings.Fields(line)
		if len(ltokens) == 0 {
			continue
		}

		switch ltokens[0] {
		case "password":
			if len(ltokens) > 1 {
				device.AddPassword(model.PasswordEntry{
					Type: "line-" + lineType,
					Hash: ltokens[1],
				})
			}
		case "login":
			if len(ltokens) > 1 && ltokens[1] == "local" {
				device.AAA.LoginLocal = true
			}
		case "exec-timeout":
			if len(ltokens) > 2 {
				minutes, _ := strconv.Atoi(ltokens[1])
				seconds, _ := strconv.Atoi(ltokens[2])
				device.General.ExecTimeout = time.Duration(minutes)*time.Minute + time.Duration(seconds)*time.Second
			}
		case "transport":
			if len(ltokens) > 2 {
				switch ltokens[1] {
				case "input":
					device.SSH.Enabled = strings.Contains(strings.ToLower(strings.Join(ltokens[2:], " ")), "ssh")
					device.Telnet.Enabled = strings.Contains(strings.ToLower(strings.Join(ltokens[2:], " ")), "telnet")
				}
			}
		case "access-class":
			if len(ltokens) > 1 {
				device.Telnet.ACLName = ltokens[1]
			}
		}
	}
}

func (p *IOSParser) processRouter(device *model.DeviceConfig, tokens []string, lines []string, idx *int) {
	if len(tokens) < 2 {
		return
	}

	protocol := tokens[1]

	switch protocol {
	case "ospf":
		ospf := &model.OSPFConfig{
			ProcessID: 1,
		}
		if len(tokens) > 2 {
			ospf.ProcessID, _ = strconv.Atoi(tokens[2])
		}

		for i := *idx + 1; i < len(lines); i++ {
			line := strings.TrimSpace(lines[i])
			if line == "" || !strings.HasPrefix(line, " ") {
				break
			}
			*idx = i
			line = strings.TrimSpace(line)
			rtokens := strings.Fields(line)
			if len(rtokens) == 0 {
				continue
			}

			switch rtokens[0] {
			case "router-id":
				if len(rtokens) > 1 {
					ospf.RouterID = rtokens[1]
				}
			case "network":
				if len(rtokens) > 3 {
					areaID, _ := strconv.Atoi(rtokens[3])
					found := false
					for j := range ospf.Areas {
						if ospf.Areas[j].ID == areaID {
							found = true
							break
						}
					}
					if !found {
						ospf.Areas = append(ospf.Areas, model.OSPFArea{
							ID: areaID,
						})
					}
				}
			case "passive-interface":
				if len(rtokens) > 1 {
					ospf.PassiveInterfaces = append(ospf.PassiveInterfaces, rtokens[1])
				}
			}
		}
		device.Routing.OSPF = ospf

	case "bgp":
		bgp := &model.BGPConfig{}
		if len(tokens) > 2 {
			bgp.ASN, _ = strconv.Atoi(tokens[2])
		}

		for i := *idx + 1; i < len(lines); i++ {
			line := strings.TrimSpace(lines[i])
			if line == "" || !strings.HasPrefix(line, " ") {
				break
			}
			*idx = i
			line = strings.TrimSpace(line)
			rtokens := strings.Fields(line)
			if len(rtokens) == 0 {
				continue
			}

			switch rtokens[0] {
			case "bgp-router-id":
				if len(rtokens) > 1 {
					bgp.RouterID = rtokens[1]
				}
			case "neighbor":
				if len(rtokens) > 2 {
					neighbor := model.BGPNeighbor{
						IP: rtokens[1],
					}
					if rtokens[2] == "remote-as" && len(rtokens) > 3 {
						neighbor.RemoteAS, _ = strconv.Atoi(rtokens[3])
					}
					bgp.Neighbors = append(bgp.Neighbors, neighbor)
				}
			}
		}
		device.Routing.BGP = bgp

	case "eigrp":
		eigrp := &model.EIGRPConfig{}
		if len(tokens) > 2 {
			eigrp.ASN, _ = strconv.Atoi(tokens[2])
		}

		for i := *idx + 1; i < len(lines); i++ {
			line := strings.TrimSpace(lines[i])
			if line == "" || !strings.HasPrefix(line, " ") {
				break
			}
			*idx = i
			line = strings.TrimSpace(line)
			rtokens := strings.Fields(line)
			if len(rtokens) == 0 {
				continue
			}

			switch rtokens[0] {
			case "passive-interface":
				if len(rtokens) > 1 {
					eigrp.PassiveInterfaces = append(eigrp.PassiveInterfaces, rtokens[1])
				}
			}
		}
		device.Routing.EIGRP = eigrp

	case "rip":
		rip := &model.RIPConfig{}
		if len(tokens) > 2 {
			switch tokens[2] {
			case "2":
				rip.Version = 2
			}
		}

		for i := *idx + 1; i < len(lines); i++ {
			line := strings.TrimSpace(lines[i])
			if line == "" || !strings.HasPrefix(line, " ") {
				break
			}
			*idx = i
			line = strings.TrimSpace(line)
			rtokens := strings.Fields(line)
			if len(rtokens) == 0 {
				continue
			}

			switch rtokens[0] {
			case "neighbor":
				if len(rtokens) > 1 {
					rip.Neighbors = append(rip.Neighbors, rtokens[1])
				}
			case "version":
				if len(rtokens) > 1 {
					rip.Version, _ = strconv.Atoi(rtokens[1])
				}
			}
		}
		device.Routing.RIPConfig = rip
	}
}

func (p *IOSParser) processSNMP(device *model.DeviceConfig, tokens []string) {
	if len(tokens) < 2 {
		return
	}

	switch tokens[1] {
	case "community":
		if len(tokens) > 2 {
			community := tokens[2]
			if device.SNMP.Community == "" || device.SNMP.Community == "public" {
				device.SNMP.Community = community
			}
			device.SNMP.Version = 2
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
	case "enable":
		if len(tokens) > 2 && tokens[2] == "traps" {
			// traps enabled
		}
	case "version":
		if len(tokens) > 2 {
			switch tokens[2] {
			case "1":
				device.SNMP.Version = 1
			case "2c":
				device.SNMP.Version = 2
			case "3":
				device.SNMP.Version = 3
			}
		}
	case "group":
		// SNMPv3 group
	case "user":
		// SNMPv3 user
		if len(tokens) > 2 {
			user := model.SNMPv3User{
				Username: tokens[2],
			}
			device.SNMP.SNMPv3Users = append(device.SNMP.SNMPv3Users, user)
		}
	}
}

func (p *IOSParser) processLogging(device *model.DeviceConfig, tokens []string) {
	if len(tokens) < 2 {
		return
	}

	device.Logging.Enabled = true

	switch tokens[1] {
	case "buffered":
		if len(tokens) > 2 {
			device.Logging.BufferSize, _ = strconv.Atoi(tokens[2])
		}
		device.Logging.LogBuffer = true
	case "console":
		if len(tokens) > 2 {
			device.Logging.ConsoleLevel, _ = strconv.Atoi(tokens[2])
		}
	case "host":
		if len(tokens) > 2 {
			device.Logging.SyslogServers = append(device.Logging.SyslogServers, tokens[2])
		}
	case "trap":
		if len(tokens) > 2 {
			device.Logging.TrapLevel, _ = strconv.Atoi(tokens[2])
		}
	case "source-interface":
		if len(tokens) > 2 {
			device.Logging.SourceInterface = tokens[2]
		}
	case "facility":
		// syslog facility
	case "datetime":
		device.Logging.Timestamps = true
	}
}

func (p *IOSParser) processBanner(device *model.DeviceConfig, tokens []string, lines []string, idx *int) {
	if len(tokens) < 2 {
		return
	}

	delimiter := tokens[1]
	if len(delimiter) == 1 {
		for i := *idx + 1; i < len(lines); i++ {
			line := lines[i]
			if strings.Contains(line, delimiter) && i != *idx+1 {
				device.General.Banner = strings.Trim(strings.TrimSpace(line), delimiter)
				break
			}
			if i == *idx+1 {
				if strings.HasPrefix(line, delimiter) {
					device.General.Banner = strings.Trim(strings.TrimPrefix(line, delimiter), delimiter)
				}
			}
		}
	}
}

func (p *IOSParser) processNTP(device *model.DeviceConfig, tokens []string) {
	if len(tokens) < 2 {
		return
	}

	switch tokens[1] {
	case "server":
		if len(tokens) > 2 {
			server := model.NTPServer{
				Address: tokens[2],
				Version: 4,
			}
			if len(tokens) > 3 && tokens[3] == "prefer" {
				server.Prefer = true
			}
			device.NTP.Servers = append(device.NTP.Servers, server)
		}
	case "authenticate":
		device.NTP.AuthEnabled = true
	case "authentication-key":
		if len(tokens) > 3 {
			device.NTP.AuthKey = tokens[3]
		}
	case "trusted-key":
		if len(tokens) > 2 {
			device.NTP.TrustedKey = tokens[2]
		}
	case "source":
		if len(tokens) > 2 {
			device.NTP.Source = tokens[2]
		}
	}
}

func (p *IOSParser) processUsername(device *model.DeviceConfig, tokens []string) {
	if len(tokens) < 2 {
		return
	}

	user := model.UserEntry{
		Username: tokens[2],
		Local:    true,
	}

	for i := 3; i < len(tokens); i++ {
		switch tokens[i] {
		case "password":
			if i+1 < len(tokens) {
				user.Password = tokens[i+1]
				i++
			}
		case "secret":
			if i+1 < len(tokens) {
				user.Password = tokens[i+1]
				user.Secret = true
				i++
			}
		case "privilege":
			if i+1 < len(tokens) {
				user.Privilege, _ = strconv.Atoi(tokens[i+1])
				i++
			}
		}
	}

	if user.Password != "" {
		device.AddPassword(model.PasswordEntry{
			Type:     "user-" + user.Username,
			Username: user.Username,
			Hash:     user.Password,
		})
	}

	device.AddUser(user)
}

func (p *IOSParser) processAAA(device *model.DeviceConfig, tokens []string) {
	if len(tokens) < 2 {
		return
	}

	switch tokens[1] {
	case "new-model":
		device.AAA.NewModel = true
	case "authentication":
		if len(tokens) > 3 && tokens[2] == "login" {
			device.AAA.AuthList = strings.Join(tokens[3:], " ")
		}
	case "authorization":
		if len(tokens) > 3 && tokens[2] == "exec" {
			device.AAA.AuthrList = strings.Join(tokens[3:], " ")
		}
	case "accounting":
		if len(tokens) > 3 && tokens[2] == "exec" {
			device.AAA.AcctList = strings.Join(tokens[3:], " ")
		}
	}
}

func (p *IOSParser) processClock(device *model.DeviceConfig, tokens []string) {
	if len(tokens) > 2 && tokens[1] == "timezone" {
		// timezone info
	}
}

func parseVLANList(s string) []int {
	var vlans []int
	parts := strings.Split(s, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			rangeParts := strings.SplitN(part, "-", 2)
			start, _ := strconv.Atoi(rangeParts[0])
			end, _ := strconv.Atoi(rangeParts[1])
			for v := start; v <= end; v++ {
				vlans = append(vlans, v)
			}
		} else {
			v, _ := strconv.Atoi(part)
			vlans = append(vlans, v)
		}
	}
	return vlans
}

func formatIP(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}
