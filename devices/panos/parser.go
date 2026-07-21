package panos

import (
	"bufio"
	"encoding/xml"
	"io"
	"strings"
	"time"

	"github.com/Cazo-Net/netpipe/internal/model"
	"github.com/Cazo-Net/netpipe/internal/parser"
)

func init() {
	parser.Register("panos", &PANOSParser{})
}

type PANOSParser struct{}

func (p *PANOSParser) Name() string {
	return "Palo Alto PAN-OS Parser"
}

func (p *PANOSParser) SupportedTypes() []model.DeviceType {
	return []model.DeviceType{model.DevicePANOS}
}

func (p *PANOSParser) Detect(data []byte) bool {
	content := string(data)
	signatures := []string{
		"<config",
		"<devices>",
		"<entry name=",
		"<deviceconfig>",
		"<vsys",
		"<rulebase>",
		"<zone",
		"<interface",
		"<ethernet",
		"<panorama",
		"<version>",
		"<auth",
		"<password",
		"<snmp-server",
		"<nls-version",
		"<device-group",
		"<template",
		"set deviceconfig",
		"set network",
		"set rulebase",
		"set shared",
		"Palo Alto",
	}
	matches := 0
	for _, sig := range signatures {
		if strings.Contains(content, sig) {
			matches++
		}
	}
	return matches >= 3
}

func (p *PANOSParser) DetectScore(data []byte) int {
	content := string(data)
	signatures := []string{
		"<config",
		"<devices>",
		"<entry name=",
		"<deviceconfig>",
		"<vsys",
		"<rulebase>",
		"<zone",
		"<interface",
		"<ethernet",
		"<panorama",
		"<version>",
		"<auth",
		"<password",
		"<snmp-server",
		"<nls-version",
		"<device-group",
		"<template",
		"set deviceconfig",
		"set network",
		"set rulebase",
		"set shared",
		"Palo Alto",
	}
	score := 0
	for _, sig := range signatures {
		if strings.Contains(content, sig) {
			score++
		}
	}
	return score
}

func (p *PANOSParser) Parse(r io.Reader, deviceType model.DeviceType) (*model.DeviceConfig, error) {
	device := &model.DeviceConfig{
		DeviceType: model.DevicePANOS,
		ParsedAt:   time.Now(),
	}

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 10*1024*1024), 10*1024*1024)

	var content strings.Builder
	for scanner.Scan() {
		content.WriteString(scanner.Text())
		content.WriteString("\n")
	}

	xmlContent := content.String()
	device.RawLines = strings.Split(xmlContent, "\n")

	if strings.HasPrefix(strings.TrimSpace(xmlContent), "<") {
		p.parseXMLConfig(device, xmlContent)
	} else {
		p.parseSetConfig(device, xmlContent)
	}

	device.SetDefaults()
	return device, nil
}

func (p *PANOSParser) parseXMLConfig(device *model.DeviceConfig, content string) {
	type PanOSConfig struct {
		XMLName  xml.Name `xml:"config"`
		Devices  struct {
			Entry []struct {
				Name         string `xml:"name,attr"`
				DeviceConfig struct {
					Hostname string `xml:"hostname"`
					LoginBanner string `xml:"login-banner"`
					Authentication struct {
						SuperUsers struct {
							Entry []struct {
								Name     string `xml:"name,attr"`
								Password string `xml:"phash"`
							} `xml:"entry"`
						} `xml:"super-users"`
					} `xml:"authentication"`
				} `xml:"deviceconfig"`
				SNMP struct {
					Server struct {
						Entry []struct {
							Name    string `xml:"name,attr"`
							Version struct {
								Enabled struct {
									V2c string `xml:"v2c"`
									V3  string `xml:"v3"`
								} `xml:"enabled"`
							} `xml:"version"`
							Community string `xml:"community"`
						} `xml:"entry"`
					} `xml:"server"`
				} `xml:"snmp-server"`
				Vsys struct {
					Entry []struct {
						Name string `xml:"name,attr"`
						Zone struct {
							Entry []struct {
								Name string `xml:"name,attr"`
							} `xml:"entry"`
						} `xml:"zone"`
						Rulebase struct {
							Security struct {
								Rules struct {
									Entry []struct {
										Name   string `xml:"name,attr"`
										Source []struct {
											Member []string `xml:"member"`
										} `xml:"source"`
										Destination []struct {
											Member []string `xml:"member"`
										} `xml:"destination"`
										Application []struct {
											Member []string `xml:"member"`
										} `xml:"application"`
										Service []struct {
											Member []string `xml:"member"`
										} `xml:"service"`
										Action string `xml:"action"`
										LogEnd string `xml:"log-end"`
									} `xml:"entry"`
								} `xml:"rules"`
							} `xml:"security"`
						} `xml:"rulebase"`
					} `xml:"entry"`
				} `xml:"vsys"`
			} `xml:"entry"`
		} `xml:"devices"`
	}

	var config PanOSConfig
	if err := xml.Unmarshal([]byte(content), &config); err != nil {
		return
	}

	if len(config.Devices.Entry) > 0 {
		dev := config.Devices.Entry[0]
		device.Hostname = dev.DeviceConfig.Hostname
		device.General.Hostname = dev.DeviceConfig.Hostname
		device.General.Banner = dev.DeviceConfig.LoginBanner
		device.DeviceName = dev.DeviceConfig.Hostname

		for _, entry := range dev.DeviceConfig.Authentication.SuperUsers.Entry {
			if entry.Password != "" {
				device.AddPassword(model.PasswordEntry{
					Type:     "panos-admin",
					Username: entry.Name,
					Hash:     entry.Password,
				})
				device.AddUser(model.UserEntry{
					Username: entry.Name,
					Password: entry.Password,
					Local:    true,
				})
			}
		}

		for _, server := range dev.SNMP.Server.Entry {
			device.SNMP.Community = server.Community
			if server.Version.Enabled.V3 == "yes" {
				device.SNMP.Version = 3
			} else if server.Version.Enabled.V2c == "yes" {
				device.SNMP.Version = 2
			}
			if server.Name != "" {
				device.SNMP.TrapServers = append(device.SNMP.TrapServers, server.Name)
			}
		}

		for _, vsys := range dev.Vsys.Entry {
			for _, zone := range vsys.Zone.Entry {
				iface := model.Interface{
					Name: zone.Name,
					Zone: zone.Name,
				}
				device.AddInterface(iface)
			}
			for _, rule := range vsys.Rulebase.Security.Rules.Entry {
				acl := model.ACL{
					Name: rule.Name,
					Type: "panos-security-rule",
				}
				for _, src := range rule.Source {
					for _, member := range src.Member {
						r := model.ACLRule{
							Action: rule.Action,
							Source: member,
							Log:    rule.LogEnd == "yes",
						}
						for _, dst := range rule.Destination {
							for _, dmember := range dst.Member {
								r.Destination = dmember
								break
							}
							break
						}
						acl.AddRule(r)
					}
				}
				device.AddACL(acl)
			}
		}
	}
}

func (p *PANOSParser) parseSetConfig(device *model.DeviceConfig, content string) {
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "set ") {
			continue
		}
		tokens := strings.Fields(line)
		if len(tokens) < 3 {
			continue
		}

		args := tokens[1:]
		if len(args) < 2 {
			continue
		}

		switch args[0] {
		case "deviceconfig":
			if len(args) > 2 && args[1] == "system" {
				switch args[2] {
				case "hostname":
					if len(args) > 3 {
						device.Hostname = args[3]
						device.General.Hostname = args[3]
						device.DeviceName = args[3]
					}
				}
			}
		case "network":
			if len(args) > 2 && args[1] == "interface" {
				if len(args) > 3 && args[2] == "ethernet" {
					iface := model.Interface{Name: args[3]}
					for i := 4; i < len(args)-1; i += 2 {
						if args[i] == "ip" {
							iface.CIDR = args[i+1]
						}
					}
					device.AddInterface(iface)
				}
			}
		case "rulebase":
			if len(args) > 3 && args[1] == "security" && args[2] == "rules" {
				ruleName := args[3]
				acl := model.ACL{Name: ruleName, Type: "panos-security-rule"}
				acl.AddRule(model.ACLRule{
					Action: "allow",
					Log:    true,
				})
				device.AddACL(acl)
			}
		case "shared":
			// shared config
		case "vsys":
			// vsys config
		case "snmp":
			if len(args) > 2 && args[1] == "server-profile" {
				// SNMP server profile
			}
		case "device-group":
			// Panorama device group
		}
	}
}
