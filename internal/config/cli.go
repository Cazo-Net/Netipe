package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Cazo-Net/Netipe/internal/model"
)

type Config struct {
	Input          string
	Output         string
	DeviceType     model.DeviceType
	Force          bool
	Location       string
	Model          string
	CompanyName    string
	DeviceName     string
	NoNames        bool
	ExpandACL      bool
	NoAudit        bool
	NoAppendix     bool
	NoAbbreviations bool
	NoLogging      bool
	NoTimezones    bool
	NoPorts        bool
	NoVersion      bool
	OutputFormat   string
	Stylesheet     string
	Paper          string
	DocumentClass  string
	DenyLog        bool
	AnySource      bool
	NetworkSource  bool
	SourceService  bool
	AnyDest        bool
	NetworkDest    bool
	DestService    bool
	LogRules       bool
	DisabledRules  bool
	RejectRules    bool
	BypassRules    bool
	DefaultRules   bool
	LogDenyRules   bool
	NoPasswords    bool
	JohnFile       string
	DictionaryFile string
	PassMinLength  int
	PassUppers     bool
	PassLowers     bool
	PassEither     bool
	PassNumbers    bool
	PassSpecials   bool
	Timeout        time.Duration
	CiscoIP        string
	LocalIP        string
	CiscoMethod    string
	SNMPCommunity  string
	TFTPRoot       string
	CiscoFile      string
	ConfigFile     string
	AutoDetect     bool
}

func DefaultConfig() *Config {
	return &Config{
		OutputFormat:  "html",
		PassMinLength: 8,
		PassEither:    true,
		PassNumbers:   true,
		DenyLog:       true,
		Timeout:       600 * time.Second,
		Location:      "edge",
		CompanyName:   "NetPipe",
	}
}

func (c *Config) Validate() error {
	if c.Input == "" && !c.Force {
		return fmt.Errorf("input file is required (use --input or stdin)")
	}
	if c.OutputFormat == "" {
		c.OutputFormat = "html"
	}
	validFormats := map[string]bool{
		"html": true, "json": true, "xml": true,
		"text": true, "latex": true, "csv": true,
	}
	if !validFormats[c.OutputFormat] {
		return fmt.Errorf("unsupported output format: %s", c.OutputFormat)
	}
	return nil
}

func ParseArgs(args []string) (*Config, error) {
	cfg := DefaultConfig()

	for i := 1; i < len(args); i++ {
		arg := args[i]

		if strings.HasPrefix(arg, "--") {
			key := strings.TrimPrefix(arg, "--")
			var value string
			eqIdx := strings.Index(key, "=")
			if eqIdx >= 0 {
				value = key[eqIdx+1:]
				key = key[:eqIdx]
			} else if i+1 < len(args) && !strings.HasPrefix(args[i+1], "--") {
				value = args[i+1]
				i++
			}

			switch key {
			case "input":
				cfg.Input = value
			case "output", "report":
				cfg.Output = value
			case "ios-router":
				cfg.DeviceType = model.DeviceIOSRouter
				cfg.Force = true
			case "ios-switch":
				cfg.DeviceType = model.DeviceIOSSwitch
				cfg.Force = true
			case "ios-catalyst":
				cfg.DeviceType = model.DeviceIOSCatalyst
				cfg.Force = true
			case "ios-xe":
				cfg.DeviceType = model.DeviceIOSXE
				cfg.Force = true
			case "ios-xr":
				cfg.DeviceType = model.DeviceIOSXR
				cfg.Force = true
			case "nxos":
				cfg.DeviceType = model.DeviceNXOS
				cfg.Force = true
			case "pix":
				cfg.DeviceType = model.DevicePIX
				cfg.Force = true
			case "asa":
				cfg.DeviceType = model.DeviceASA
				cfg.Force = true
			case "fwsm":
				cfg.DeviceType = model.DeviceFWSM
				cfg.Force = true
			case "nmp":
				cfg.DeviceType = model.DeviceNMP
				cfg.Force = true
			case "catos":
				cfg.DeviceType = model.DeviceCatOS
				cfg.Force = true
			case "css":
				cfg.DeviceType = model.DeviceCSS
				cfg.Force = true
			case "screenos":
				cfg.DeviceType = model.DeviceScreenOS
				cfg.Force = true
			case "junos":
				cfg.DeviceType = model.DeviceJunos
				cfg.Force = true
			case "fw1":
				cfg.DeviceType = model.DeviceFW1
				cfg.Force = true
			case "passport":
				cfg.DeviceType = model.DevicePassport
				cfg.Force = true
			case "sonicos":
				cfg.DeviceType = model.DeviceSonicOS
				cfg.Force = true
			case "panos":
				cfg.DeviceType = model.DevicePANOS
				cfg.Force = true
			case "fortios":
				cfg.DeviceType = model.DeviceFortiOS
				cfg.Force = true
			case "eos":
				cfg.DeviceType = model.DeviceEOS
				cfg.Force = true
			case "bigip":
				cfg.DeviceType = model.DeviceBIGIP
				cfg.Force = true
			case "html":
				cfg.OutputFormat = "html"
			case "json":
				cfg.OutputFormat = "json"
			case "xml":
				cfg.OutputFormat = "xml"
			case "text":
				cfg.OutputFormat = "text"
			case "latex":
				cfg.OutputFormat = "latex"
			case "csv":
				cfg.OutputFormat = "csv"
			case "force":
				cfg.Force = true
			case "location":
				cfg.Location = value
			case "model":
				cfg.Model = value
			case "company-name":
				cfg.CompanyName = value
			case "device-name":
				cfg.DeviceName = value
			case "no-names":
				cfg.NoNames = true
			case "expand-acl":
				cfg.ExpandACL = true
			case "no-audit":
				cfg.NoAudit = true
			case "no-appendix":
				cfg.NoAppendix = true
			case "no-abbreviations":
				cfg.NoAbbreviations = true
			case "no-logging":
				cfg.NoLogging = true
			case "no-timezones":
				cfg.NoTimezones = true
			case "no-ports":
				cfg.NoPorts = true
			case "no-version":
				cfg.NoVersion = true
			case "stylesheet":
				cfg.Stylesheet = value
			case "paper":
				cfg.Paper = value
			case "documentclass":
				cfg.DocumentClass = value
			case "deny-log":
				cfg.DenyLog = true
			case "no-deny-log":
				cfg.DenyLog = false
			case "any-source":
				cfg.AnySource = true
			case "no-any-source":
				cfg.AnySource = false
			case "network-source":
				cfg.NetworkSource = true
			case "no-network-source":
				cfg.NetworkSource = false
			case "source-service":
				cfg.SourceService = true
			case "no-source-service":
				cfg.SourceService = false
			case "any-destination":
				cfg.AnyDest = true
			case "no-any-destination":
				cfg.AnyDest = false
			case "network-destination":
				cfg.NetworkDest = true
			case "no-network-destination":
				cfg.NetworkDest = false
			case "destination-service":
				cfg.DestService = true
			case "no-destination-service":
				cfg.DestService = false
			case "log-rules":
				cfg.LogRules = true
			case "no-log-rules":
				cfg.LogRules = false
			case "disabled-rules":
				cfg.DisabledRules = true
			case "no-disabled-rules":
				cfg.DisabledRules = false
			case "reject-rules":
				cfg.RejectRules = true
			case "no-reject-rules":
				cfg.RejectRules = false
			case "bypass-rules":
				cfg.BypassRules = true
			case "no-bypass-rules":
				cfg.BypassRules = false
			case "default-rules":
				cfg.DefaultRules = true
			case "no-default-rules":
				cfg.DefaultRules = false
			case "log-deny-rules":
				cfg.LogDenyRules = true
			case "no-log-deny-rules":
				cfg.LogDenyRules = false
			case "no-passwords":
				cfg.NoPasswords = true
			case "john":
				cfg.JohnFile = value
			case "dictionary":
				cfg.DictionaryFile = value
			case "pass-length":
				fmt.Sscanf(value, "%d", &cfg.PassMinLength)
			case "pass-uppers":
				cfg.PassUppers = value == "yes"
			case "pass-lowers":
				cfg.PassLowers = value == "yes"
			case "pass-either":
				cfg.PassEither = value == "yes"
			case "pass-numbers":
				cfg.PassNumbers = value == "yes"
			case "pass-specials":
				cfg.PassSpecials = value == "yes"
			case "cisco-ip":
				cfg.CiscoIP = value
			case "local-ip":
				cfg.LocalIP = value
			case "cisco":
				cfg.CiscoMethod = value
			case "snmp":
				cfg.SNMPCommunity = value
			case "tftproot":
				cfg.TFTPRoot = value
			case "cisco-file":
				cfg.CiscoFile = value
			case "config":
				cfg.ConfigFile = value
			case "version":
				PrintVersion()
				os.Exit(0)
			case "help":
				PrintHelp(value)
				os.Exit(0)
			case "auto-detect":
				cfg.AutoDetect = true
			default:
				return nil, fmt.Errorf("unknown option: --%s", key)
			}
		} else if cfg.Input == "" {
			cfg.Input = arg
		}
	}

	return cfg, nil
}

func PrintVersion() {
	fmt.Println("NetPipe v1.0.0")
	fmt.Println("Network Infrastructure Configuration Parser and Security Auditor")
	fmt.Println("Based on nipper-ng v0.11.10 by Ian Ventura-Whiting")
	fmt.Println("Rewritten in Go by the NetPipe contributors")
	fmt.Println("License: GPL v3")
}

func PrintHelp(topic string) {
	topics := map[string]string{
		"": `NetPipe - Network Infrastructure Configuration Parser and Security Auditor

Usage:
    netpipe [options] [input-file]

General Options:
    --input=<file>          Device configuration file to process
    --output=<file>         Output file for the report
    --version               Display version information
    --help                  Show this help message
    --auto-detect           Auto-detect device type from config

Device Types:
    --ios-router            Cisco IOS Router (default)
    --ios-switch            Cisco IOS Switch
    --ios-catalyst          Cisco IOS Catalyst
    --ios-xe                Cisco IOS-XE
    --ios-xr                Cisco IOS-XR
    --nxos                  Cisco NX-OS
    --pix                   Cisco PIX Firewall
    --asa                   Cisco ASA Firewall
    --fwsm                  Cisco FWSM Firewall
    --nmp                   Cisco NMP/CatOS Catalyst
    --css                   Cisco Content Services Switch
    --screenos              Juniper NetScreen ScreenOS
    --junos                 Juniper Junos
    --fw1                   CheckPoint Firewall-1
    --passport              Nortel Passport
    --sonicos               SonicWall SonicOS
    --panos                 Palo Alto PAN-OS
    --fortios               Fortinet FortiOS
    --eos                   Arista EOS
    --bigip                 F5 BIG-IP

Output Formats:
    --html                  HTML (default)
    --json                  JSON
    --xml                   XML
    --text                  Plain text
    --latex                 LaTeX
    --csv                   CSV (ACL export)

Report Sections:
    --no-audit              Disable security audit
    --no-appendix           Disable appendix section
    --company-name=<name>   Custom company name in report

Password Audit:
    --no-passwords          Remove passwords from output
    --john=<file>           Export type-5 passwords for John the Ripper
    --dictionary=<file>     Custom dictionary file for password checks
    --pass-length=<len>     Minimum password length (default: 8)

ACL Audit:
    --deny-log / --no-deny-log         Check deny-all+log
    --any-source / --no-any-source     Check any source
    --log-rules / --no-log-rules       Check logging on all rules

Advanced:
    --force                 Bypass device type checks
    --location=<edge|internal>   Device location
    --device-name=<name>    Device name override`,
	}

	if help, ok := topics[topic]; ok {
		fmt.Println(help)
	} else {
		fmt.Println("Available help topics: GENERAL, DEVICE, REPORT, AUDIT, SNMP, ADVANCED")
	}
}
