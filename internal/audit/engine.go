package audit

import (
	"fmt"
	"strings"
	"time"

	"github.com/Cazo-Net/netpipe/internal/config"
	"github.com/Cazo-Net/netpipe/internal/model"
	"github.com/Cazo-Net/netpipe/internal/util"
)

type Finding struct {
	ID          string
	Title       string
	Description string
	Impact      string
	Recommendation string
	Severity    model.Severity
	Category    string
	Details     string
	FixCommand  string
	Reference   string
	CVE         string
}

type AuditResult struct {
	Findings    []Finding
	Summary     AuditSummary
}

type AuditSummary struct {
	Critical    int
	High        int
	Medium      int
	Low         int
	Info        int
	Total       int
}

func (a *AuditResult) AddFinding(f Finding) {
	a.Findings = append(a.Findings, f)
	switch f.Severity {
	case model.SeverityCritical:
		a.Summary.Critical++
	case model.SeverityHigh:
		a.Summary.High++
	case model.SeverityMedium:
		a.Summary.Medium++
	case model.SeverityLow:
		a.Summary.Low++
	case model.SeverityInfo:
		a.Summary.Info++
	}
	a.Summary.Total++
}

type AuditEngine struct {
	cfg    *config.Config
	result *AuditResult
}

func NewEngine(cfg *config.Config) *AuditEngine {
	return &AuditEngine{
		cfg:    cfg,
		result: &AuditResult{},
	}
}

func RunAudit(device *model.DeviceConfig, cfg *config.Config) *AuditResult {
	engine := &AuditEngine{cfg: cfg, result: &AuditResult{}}

	if cfg.NoAudit {
		return engine.result
	}

	engine.auditPasswords(device)
	engine.auditSNMP(device)
	engine.auditACLs(device)
	engine.auditGeneral(device)
	engine.auditInterfaces(device)
	engine.auditSSH(device)
	engine.auditTelnet(device)
	engine.auditHTTP(device)
	engine.auditLogging(device)
	engine.auditNTP(device)
	engine.auditRouting(device)
	engine.auditAAA(device)
	engine.auditBanner(device)

	return engine.result
}

func (e *AuditEngine) auditPasswords(device *model.DeviceConfig) {
	for _, pw := range device.Passwords {
		if pw.Type == "type7" {
			decoded, err := util.DecodeType7(pw.Hash)
			if err == nil && decoded != "" {
				e.result.AddFinding(Finding{
					ID:          "PW-T7-001",
					Title:       "Cisco Type 7 Password Detected",
					Description: fmt.Sprintf("A Cisco Type 7 password is used for user '%s'. Type 7 passwords are weakly obfuscated and can be trivially decoded.", pw.Username),
					Impact:      "Passwords can be recovered instantly, allowing unauthorized access to the device.",
					Recommendation: "Use 'enable secret' (Type 5) instead of 'enable password' (Type 7). Use 'service password-encryption' only as a last resort.",
					Severity:    model.SeverityHigh,
					Category:    "Password Security",
					FixCommand:  "enable secret <strong-password>",
					Reference:   "CISCO-2001-02",
				})
			}
		}

		result := util.CheckPassword(pw.Hash, e.cfg.PassMinLength, e.cfg.DictionaryFile)

		if result.IsDefault {
			e.result.AddFinding(Finding{
				ID:          "PW-DEF-001",
				Title:       fmt.Sprintf("Default Password Detected for '%s'", pw.Username),
				Description: fmt.Sprintf("A default password is configured for user '%s'.", pw.Username),
				Impact:      "Default passwords are publicly known and provide no security.",
				Recommendation: "Set a strong, unique password for each user account.",
				Severity:    model.SeverityCritical,
				Category:    "Password Security",
			})
		}

		if result.IsDictionary {
			e.result.AddFinding(Finding{
				ID:          "PW-DICT-001",
				Title:       fmt.Sprintf("Dictionary-Based Password for '%s'", pw.Username),
				Description: fmt.Sprintf("The password for user '%s' contains or matches a dictionary word.", pw.Username),
				Impact:      "Dictionary-based passwords can be cracked quickly with brute-force attacks.",
				Recommendation: "Use a random password with mixed case, numbers, and special characters.",
				Severity:    model.SeverityHigh,
				Category:    "Password Security",
			})
		}

		if result.IsWeak {
			e.result.AddFinding(Finding{
				ID:          "PW-WEAK-001",
				Title:       fmt.Sprintf("Weak Password for '%s'", pw.Username),
				Description: fmt.Sprintf("The password for user '%s' does not meet minimum strength requirements.", pw.Username),
				Impact:      "Weak passwords can be guessed or brute-forced.",
				Recommendation: fmt.Sprintf("Set a password with minimum %d characters, including upper/lowercase, numbers, and special characters.", e.cfg.PassMinLength),
				Severity:    model.SeverityMedium,
				Category:    "Password Security",
			})
		}
	}
}

func (e *AuditEngine) auditSNMP(device *model.DeviceConfig) {
	snmp := device.SNMP

	if snmp.Version == 1 || snmp.Version == 2 {
		versionStr := fmt.Sprintf("v%d", snmp.Version)
		e.result.AddFinding(Finding{
			ID:          "SNMP-VER-001",
			Title:       fmt.Sprintf("SNMP %s Enabled", versionStr),
			Description: fmt.Sprintf("SNMP %s is configured on this device. SNMP v1/v2c transmit community strings in cleartext.", versionStr),
			Impact:      "SNMP v1/v2 community strings can be intercepted, allowing unauthorized access to device configuration and data.",
			Recommendation: "Disable SNMP v1/v2 and use SNMP v3 with authentication and encryption.",
			Severity:    model.SeverityHigh,
			Category:    "SNMP Security",
			FixCommand:  "no snmp-server community <community>\nno snmp-server enable traps\nsnmp-server group <name> v3 priv\nsnmp-server user <user> <group> v3 auth sha <pass> priv aes 128 <pass>",
			Reference:   "CISCO-2002-03",
		})
	}

	if util.IsDefaultCommunity(snmp.Community) {
		e.result.AddFinding(Finding{
			ID:          "SNMP-COM-001",
			Title:       "Default SNMP Community String",
			Description: fmt.Sprintf("A default SNMP community string '%s' is configured.", snmp.Community),
			Impact:      "Default community strings are publicly known and provide unrestricted access.",
			Recommendation: "Change community strings to complex, unique values or migrate to SNMPv3.",
			Severity:    model.SeverityCritical,
			Category:    "SNMP Security",
			FixCommand:  "no snmp-server community public\nno snmp-server community private",
		})
	}

	if util.IsDefaultCommunity(snmp.ReadOnlyComm) {
		e.result.AddFinding(Finding{
			ID:          "SNMP-COM-002",
			Title:       "Default SNMP Read-Only Community",
			Description: fmt.Sprintf("A default read-only community string '%s' is configured.", snmp.ReadOnlyComm),
			Severity:    model.SeverityHigh,
			Category:    "SNMP Security",
		})
	}

	if util.IsDefaultCommunity(snmp.ReadWriteComm) {
		e.result.AddFinding(Finding{
			ID:          "SNMP-COM-003",
			Title:       "Default SNMP Read-Write Community",
			Description: fmt.Sprintf("A default read-write community string '%s' is configured.", snmp.ReadWriteComm),
			Severity:    model.SeverityCritical,
			Category:    "SNMP Security",
		})
	}

	if snmp.ACLName == "" {
		e.result.AddFinding(Finding{
			ID:          "SNMP-ACL-001",
			Title:       "No SNMP Access Control List",
			Description: "No ACL is configured to restrict SNMP access.",
			Impact:      "Any host can query the device via SNMP.",
			Recommendation: "Apply an ACL to restrict SNMP access to authorized management stations.",
			Severity:    model.SeverityMedium,
			Category:    "SNMP Security",
		})
	}
}

func (e *AuditEngine) auditACLs(device *model.DeviceConfig) {
	for _, acl := range device.ACLs {
		for _, rule := range acl.Rules {
			if rule.Source == "any" && rule.Destination == "any" {
				e.result.AddFinding(Finding{
					ID:          "ACL-ANY-001",
					Title:       fmt.Sprintf("Overly Permissive ACL Rule in %s", acl.Name),
					Description: fmt.Sprintf("ACL '%s' contains a rule permitting traffic from any source to any destination.", acl.Name),
					Impact:      "This rule effectively permits all traffic, negating the firewall policy.",
					Recommendation: "Replace 'any-to-any' rules with specific source/destination pairs.",
					Severity:    model.SeverityHigh,
					Category:    "ACL Security",
				})
			}

			if rule.Action == "permit" && rule.Source == "any" {
				e.result.AddFinding(Finding{
					ID:          "ACL-ANY-002",
					Title:       fmt.Sprintf("Any Source Permit in %s", acl.Name),
					Description: fmt.Sprintf("ACL '%s' contains a rule permitting traffic from any source.", acl.Name),
					Severity:    model.SeverityMedium,
					Category:    "ACL Security",
				})
			}

			if !rule.Log && rule.Action == "permit" && e.cfg.LogRules {
				e.result.AddFinding(Finding{
					ID:          "ACL-LOG-001",
					Title:       fmt.Sprintf("ACL Rule Without Logging in %s", acl.Name),
					Description: fmt.Sprintf("A permit rule in ACL '%s' does not have logging enabled.", acl.Name),
					Severity:    model.SeverityLow,
					Category:    "ACL Security",
				})
			}
		}

		hasDenyAll := false
		for _, rule := range acl.Rules {
			if rule.Action == "deny" && rule.Source == "any" && rule.Destination == "any" {
				hasDenyAll = true
				break
			}
		}

		if !hasDenyAll && e.cfg.DenyLog {
			e.result.AddFinding(Finding{
				ID:          "ACL-DENY-001",
				Title:       fmt.Sprintf("Missing Deny-All Rule in %s", acl.Name),
				Description: fmt.Sprintf("ACL '%s' does not end with a deny-all rule.", acl.Name),
				Impact:      "Without a deny-all rule, traffic not explicitly matched may be permitted.",
				Recommendation: "Add 'deny ip any any log' as the last rule in the ACL.",
				Severity:    model.SeverityMedium,
				Category:    "ACL Security",
			})
		}
	}
}

func (e *AuditEngine) auditGeneral(device *model.DeviceConfig) {
	gen := device.General

	if gen.IPSourceRouting {
		e.result.AddFinding(Finding{
			ID:          "GEN-SR-001",
			Title:       "IP Source Routing Enabled",
			Description: "IP source route processing is enabled on this device.",
			Impact:      "Source routing can be used to bypass access controls and routing policies.",
			Recommendation: "Disable source routing: 'no ip source-route'.",
			Severity:    model.SeverityHigh,
			Category:    "General Security",
			FixCommand:  "no ip source-route",
		})
	}

	if gen.ProxyARP {
		e.result.AddFinding(Finding{
			ID:          "GEN-PAR-001",
			Title:       "Proxy ARP Enabled",
			Description: "Proxy ARP is enabled on one or more interfaces.",
			Impact:      "Proxy ARP can be used to redirect traffic and bypass network segmentation.",
			Recommendation: "Disable proxy ARP on all interfaces: 'no ip proxy-arp'.",
			Severity:    model.SeverityMedium,
			Category:    "General Security",
			FixCommand:  "interface <name>\n  no ip proxy-arp",
		})
	}

	if gen.CDPEnabled {
		e.result.AddFinding(Finding{
			ID:          "GEN-CDP-001",
			Title:       "CDP Enabled",
			Description: "Cisco Discovery Protocol (CDP) is enabled, advertising device information.",
			Impact:      "CDP exposes device type, IOS version, IP addresses, and platform information to neighbors.",
			Recommendation: "Disable CDP globally or on edge interfaces.",
			Severity:    model.SeverityMedium,
			Category:    "General Security",
			FixCommand:  "no cdp run",
		})
	}

	if gen.Finger {
		e.result.AddFinding(Finding{
			ID:          "GEN-FING-001",
			Title:       "Finger Service Enabled",
			Description: "The Finger service is enabled, which can expose user information.",
			Severity:    model.SeverityLow,
			Category:    "General Security",
			FixCommand:  "no service finger",
		})
	}

	if gen.IPBootpServer {
		e.result.AddFinding(Finding{
			ID:          "GEN-BOOT-001",
			Title:       "BOOTP Server Enabled",
			Description: "The BOOTP server is enabled, which can be used for IP address allocation.",
			Severity:    model.SeverityLow,
			Category:    "General Security",
			FixCommand:  "no ip bootp server",
		})
	}

	if gen.HTTPServer && !device.HTTP.SSL {
		e.result.AddFinding(Finding{
			ID:          "GEN-HTTP-001",
			Title:       "HTTP Server Enabled (Unencrypted)",
			Description: "The HTTP server is enabled without SSL/TLS encryption.",
			Impact:      "Device management traffic is transmitted in cleartext.",
			Recommendation: "Enable HTTPS: 'ip http secure-server'.",
			Severity:    model.SeverityHigh,
			Category:    "General Security",
			FixCommand:  "ip http secure-server",
		})
	}

	if gen.EnablePassword != "" {
		e.result.AddFinding(Finding{
			ID:          "GEN-ENP-001",
			Title:       "Enable Password (Not Secret) Configured",
			Description: "The device uses 'enable password' instead of 'enable secret'.",
			Impact:      "Enable password is weakly obfuscated and can be decoded.",
			Recommendation: "Use 'enable secret' with a strong password instead.",
			Severity:    model.SeverityMedium,
			Category:    "General Security",
			FixCommand:  "no enable password\nenable secret <strong-password>",
		})
	}

	if gen.ExecTimeout > 10*time.Minute {
		e.result.AddFinding(Finding{
			ID:          "GEN-TIME-001",
			Title:       "Excessive Exec Timeout",
			Description: fmt.Sprintf("The exec timeout is set to %v, which exceeds the recommended 10 minutes.", gen.ExecTimeout),
			Impact:      "Idle sessions may be hijacked by unauthorized users.",
			Recommendation: "Set exec timeout to 5-10 minutes: 'exec-timeout 5 0'.",
			Severity:    model.SeverityMedium,
			Category:    "General Security",
			FixCommand:  "line vty 0 4\n  exec-timeout 5 0",
		})
	}
}

func (e *AuditEngine) auditInterfaces(device *model.DeviceConfig) {
	for _, iface := range device.Interfaces {
		if iface.ProxyARP {
			e.result.AddFinding(Finding{
				ID:          fmt.Sprintf("IF-PAR-%s", iface.Name),
				Title:       fmt.Sprintf("Proxy ARP on Interface %s", iface.Name),
				Description: fmt.Sprintf("Proxy ARP is enabled on interface %s.", iface.Name),
				Severity:    model.SeverityMedium,
				Category:    "Interface Security",
			})
		}

		if iface.CDPEnabled {
			e.result.AddFinding(Finding{
				ID:          fmt.Sprintf("IF-CDP-%s", iface.Name),
				Title:       fmt.Sprintf("CDP on Interface %s", iface.Name),
				Description: fmt.Sprintf("CDP is enabled on interface %s, which may expose device information on edge interfaces.", iface.Name),
				Severity:    model.SeverityMedium,
				Category:    "Interface Security",
			})
		}

		if iface.ACLName == "" && iface.ACLIn == "" && iface.ACLEdge() {
			e.result.AddFinding(Finding{
				ID:          fmt.Sprintf("IF-NOACL-%s", iface.Name),
				Title:       fmt.Sprintf("No ACL on Edge Interface %s", iface.Name),
				Description: fmt.Sprintf("No access control list is applied to edge interface %s.", iface.Name),
				Severity:    model.SeverityMedium,
				Category:    "Interface Security",
			})
		}
	}
}

func (e *AuditEngine) auditSSH(device *model.DeviceConfig) {
	ssh := device.SSH

	if ssh.Enabled && ssh.Version == 1 {
		e.result.AddFinding(Finding{
			ID:          "SSH-V1-001",
			Title:       "SSHv1 Enabled",
			Description: "SSH version 1 is enabled, which has known vulnerabilities.",
			Impact:      "SSHv1 is vulnerable to MITM attacks and has weak encryption.",
			Recommendation: "Disable SSHv1 and use SSHv2 only: 'ip ssh version 2'.",
			Severity:    model.SeverityHigh,
			Category:    "SSH Security",
			FixCommand:  "ip ssh version 2",
		})
	}

	if !ssh.Enabled {
		e.result.AddFinding(Finding{
			ID:          "SSH-DIS-001",
			Title:       "SSH Not Enabled",
			Description: "SSH is not enabled on this device, potentially requiring Telnet for remote management.",
			Severity:    model.SeverityMedium,
			Category:    "SSH Security",
		})
	}

	if ssh.AuthRetries > 5 {
		e.result.AddFinding(Finding{
			ID:          "SSH-RETRY-001",
			Title:       "Excessive SSH Authentication Retries",
			Description: fmt.Sprintf("SSH authentication retries set to %d, exceeding recommended maximum of 5.", ssh.AuthRetries),
			Severity:    model.SeverityLow,
			Category:    "SSH Security",
		})
	}

	if ssh.MaxSessions > 5 {
		e.result.AddFinding(Finding{
			ID:          "SSH-SESS-001",
			Title:       "Excessive SSH Max Sessions",
			Description: fmt.Sprintf("SSH max sessions set to %d, which may be excessive.", ssh.MaxSessions),
			Severity:    model.SeverityLow,
			Category:    "SSH Security",
		})
	}
}

func (e *AuditEngine) auditTelnet(device *model.DeviceConfig) {
	if device.Telnet.Enabled {
		e.result.AddFinding(Finding{
			ID:          "TEL-EN-001",
			Title:       "Telnet Enabled",
			Description: "Telnet is enabled for remote management. Telnet transmits all data including passwords in cleartext.",
			Impact:      "All session data including credentials can be intercepted.",
			Recommendation: "Disable Telnet and use SSH instead: 'no transport input telnet'.",
			Severity:    model.SeverityHigh,
			Category:    "Telnet Security",
			FixCommand:  "line vty 0 4\n  transport input ssh",
		})
	}
}

func (e *AuditEngine) auditHTTP(device *model.DeviceConfig) {
	if device.HTTP.Enabled && !device.HTTP.SSL {
		e.result.AddFinding(Finding{
			ID:          "HTTP-SSL-001",
			Title:       "HTTP Enabled Without SSL",
			Description: "The HTTP server is enabled but SSL is not configured.",
			Severity:    model.SeverityHigh,
			Category:    "HTTP Security",
		})
	}
}

func (e *AuditEngine) auditLogging(device *model.DeviceConfig) {
	log := device.Logging

	if !log.Enabled {
		e.result.AddFinding(Finding{
			ID:          "LOG-DIS-001",
			Title:       "Logging Not Enabled",
			Description: "Logging is not enabled on this device.",
			Impact:      "Without logging, security events and configuration changes cannot be audited.",
			Recommendation: "Enable logging: 'logging buffered 64000'.",
			Severity:    model.SeverityMedium,
			Category:    "Logging Security",
		})
		return
	}

	if log.ConsoleLevel < 4 {
		e.result.AddFinding(Finding{
			ID:          "LOG-CON-001",
			Title:       "Low Console Logging Level",
			Description: fmt.Sprintf("Console logging level is %d, which may miss important security events.", log.ConsoleLevel),
			Severity:    model.SeverityLow,
			Category:    "Logging Security",
		})
	}

	if len(log.SyslogServers) == 0 {
		e.result.AddFinding(Finding{
			ID:          "LOG-REM-001",
			Title:       "No Remote Syslog Server Configured",
			Description: "No remote syslog server is configured. Logs may be lost if the device is compromised.",
			Recommendation: "Configure at least one remote syslog server: 'logging host <ip>'.",
			Severity:    model.SeverityMedium,
			Category:    "Logging Security",
		})
	}

	if !log.Timestamps {
		e.result.AddFinding(Finding{
			ID:          "LOG-TS-001",
			Title:       "Log Timestamps Disabled",
			Description: "Log timestamps are disabled, making incident response difficult.",
			Severity:    model.SeverityLow,
			Category:    "Logging Security",
		})
	}

	if log.SourceInterface == "" {
		e.result.AddFinding(Finding{
			ID:          "LOG-SRC-001",
			Title:       "No Logging Source Interface",
			Description: "No logging source interface is configured.",
			Severity:    model.SeverityInfo,
			Category:    "Logging Security",
		})
	}
}

func (e *AuditEngine) auditNTP(device *model.DeviceConfig) {
	ntp := device.NTP

	if len(ntp.Servers) == 0 {
		e.result.AddFinding(Finding{
			ID:          "NTP-NO-001",
			Title:       "No NTP Server Configured",
			Description: "No NTP server is configured. Inconsistent time can affect log correlation and certificate validation.",
			Severity:    model.SeverityMedium,
			Category:    "NTP Security",
		})
		return
	}

	if !ntp.AuthEnabled {
		e.result.AddFinding(Finding{
			ID:          "NTP-AUTH-001",
			Title:       "NTP Authentication Not Enabled",
			Description: "NTP authentication is not enabled, allowing unauthorized time synchronization.",
			Recommendation: "Enable NTP authentication: 'ntp authenticate'.",
			Severity:    model.SeverityMedium,
			Category:    "NTP Security",
		})
	}

	for _, server := range ntp.Servers {
		if server.Version < 4 {
			e.result.AddFinding(Finding{
				ID:          "NTP-VER-001",
				Title:       fmt.Sprintf("NTP Server %s Using v%d", server.Address, server.Version),
				Description: fmt.Sprintf("NTP server %s is using version %d. NTP v4 is recommended.", server.Address, server.Version),
				Severity:    model.SeverityInfo,
				Category:    "NTP Security",
			})
		}
	}
}

func (e *AuditEngine) auditRouting(device *model.DeviceConfig) {
	routing := device.Routing

	if routing.SourceRouting {
		e.result.AddFinding(Finding{
			ID:          "RTE-SR-001",
			Title:       "Source Routing Enabled",
			Description: "IP source routing is enabled in the routing configuration.",
			Severity:    model.SeverityHigh,
			Category:    "Routing Security",
			FixCommand:  "no ip source-route",
		})
	}

	if routing.OSPF != nil {
		ospf := routing.OSPF
		for _, area := range ospf.Areas {
			if area.AuthType == "" || area.AuthType == "none" {
				e.result.AddFinding(Finding{
					ID:          fmt.Sprintf("RTE-OSPF-AUTH-%d", area.ID),
					Title:       fmt.Sprintf("OSPF Area %d Has No Authentication", area.ID),
					Description: fmt.Sprintf("OSPF area %d does not have authentication configured.", area.ID),
					Impact:      "Unauthenticated OSPF adjacencies can be established by unauthorized routers.",
					Recommendation: "Enable OSPF authentication: 'area <id> authentication'.",
					Severity:    model.SeverityHigh,
					Category:    "Routing Security",
				})
			}
		}
	}

	if routing.BGP != nil {
		bgp := routing.BGP
		for _, neighbor := range bgp.Neighbors {
			if neighbor.AuthKey == "" {
				e.result.AddFinding(Finding{
					ID:          fmt.Sprintf("RTE-BGP-AUTH-%s", neighbor.IP),
					Title:       fmt.Sprintf("BGP Neighbor %s Has No Authentication", neighbor.IP),
					Description: fmt.Sprintf("BGP neighbor %s does not have authentication configured.", neighbor.IP),
					Impact:      "Unauthorized BGP peers can establish sessions and inject routes.",
					Recommendation: "Enable BGP authentication: 'neighbor <ip> password <key>'.",
					Severity:    model.SeverityHigh,
					Category:    "Routing Security",
				})
			}
		}
	}

	if routing.EIGRP != nil {
		if routing.EIGRP.AuthKey == "" {
			e.result.AddFinding(Finding{
				ID:          "RTE-EIGRP-AUTH-001",
				Title:       "EIGRP Has No Authentication",
				Description: "EIGRP does not have authentication configured.",
				Severity:    model.SeverityHigh,
				Category:    "Routing Security",
			})
		}
	}
}

func (e *AuditEngine) auditAAA(device *model.DeviceConfig) {
	aaa := device.AAA

	if !aaa.NewModel {
		e.result.AddFinding(Finding{
			ID:          "AAA-NEW-001",
			Title:       "AAA 'New Model' Not Enabled",
			Description: "The 'aaa new-model' command is not enabled. Legacy authentication methods are in use.",
			Recommendation: "Enable AAA: 'aaa new-model' and configure TACACS+ or RADIUS.",
			Severity:    model.SeverityMedium,
			Category:    "AAA Security",
		})
	}

	if aaa.LoginLocal && !aaa.NewModel {
		e.result.AddFinding(Finding{
			ID:          "AAA-LOCAL-001",
			Title:       "Local Login Without AAA",
			Description: "Local login is used without AAA, providing no centralized authentication.",
			Severity:    model.SeverityMedium,
			Category:    "AAA Security",
		})
	}

	if aaa.TacacsKey != "" {
		result := util.CheckPassword(aaa.TacacsKey, 8, e.cfg.DictionaryFile)
		if result.IsWeak {
			e.result.AddFinding(Finding{
				ID:          "AAA-TKEY-001",
				Title:       "Weak TACACS+ Key",
				Description: "The TACACS+ key is weak or uses a default value.",
				Severity:    model.SeverityHigh,
				Category:    "AAA Security",
			})
		}
	}

	if aaa.RadKey != "" {
		result := util.CheckPassword(aaa.RadKey, 8, e.cfg.DictionaryFile)
		if result.IsWeak {
			e.result.AddFinding(Finding{
				ID:          "AAA-RKEY-001",
				Title:       "Weak RADIUS Key",
				Description: "The RADIUS key is weak or uses a default value.",
				Severity:    model.SeverityHigh,
				Category:    "AAA Security",
			})
		}
	}
}

func (e *AuditEngine) auditBanner(device *model.DeviceConfig) {
	banner := device.General.Banner

	if banner == "" {
		e.result.AddFinding(Finding{
			ID:          "BAN-EMP-001",
			Title:       "No Banner Configured",
			Description: "No login banner is configured on this device.",
			Impact:      "Without a legal banner, unauthorized access may not be legally actionable.",
			Recommendation: "Configure a legal warning banner.",
			Severity:    model.SeverityLow,
			Category:    "Banner Security",
			FixCommand:  "banner motd #Unauthorized access prohibited#",
		})
		return
	}

	lower := strings.ToLower(banner)
	if !strings.Contains(lower, "unauthorized") && !strings.Contains(lower, "warning") && !strings.Contains(lower, "notice") {
		e.result.AddFinding(Finding{
			ID:          "BAN-WEAK-001",
			Title:       "Weak Banner Message",
			Description: "The configured banner does not contain standard legal warning language.",
			Severity:    model.SeverityInfo,
			Category:    "Banner Security",
		})
	}
}
