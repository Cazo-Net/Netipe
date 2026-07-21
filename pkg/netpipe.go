package netpipe

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/netpipe/netpipe/internal/audit"
	"github.com/netpipe/netpipe/internal/config"
	"github.com/netpipe/netpipe/internal/model"
	"github.com/netpipe/netpipe/internal/parser"
	"github.com/netpipe/netpipe/internal/report"

	_ "github.com/netpipe/netpipe/devices/bigip"
	_ "github.com/netpipe/netpipe/devices/css"
	_ "github.com/netpipe/netpipe/devices/eos"
	_ "github.com/netpipe/netpipe/devices/fortios"
	_ "github.com/netpipe/netpipe/devices/fw1"
	_ "github.com/netpipe/netpipe/devices/ios"
	_ "github.com/netpipe/netpipe/devices/iosxe"
	_ "github.com/netpipe/netpipe/devices/iosxr"
	_ "github.com/netpipe/netpipe/devices/junos"
	_ "github.com/netpipe/netpipe/devices/nmp"
	_ "github.com/netpipe/netpipe/devices/nxos"
	_ "github.com/netpipe/netpipe/devices/panos"
	_ "github.com/netpipe/netpipe/devices/passport"
	_ "github.com/netpipe/netpipe/devices/pixasa"
	_ "github.com/netpipe/netpipe/devices/screenos"
	_ "github.com/netpipe/netpipe/devices/sonicos"
)

type Engine struct {
	Config *config.Config
}

func New(cfg *config.Config) *Engine {
	return &Engine{Config: cfg}
}

func (e *Engine) Run() error {
	var r io.Reader

	if e.Config.Input == "" || e.Config.Input == "-" {
		r = os.Stdin
	} else {
		f, err := os.Open(e.Config.Input)
		if err != nil {
			return fmt.Errorf("failed to open input file: %w", err)
		}
		defer f.Close()
		r = f
	}

	data, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("failed to read input: %w", err)
	}

	var deviceParser parser.DeviceParser
	deviceType := e.Config.DeviceType

	if deviceType == model.DeviceUnknown || (!e.Config.Force && deviceType == "") {
		deviceType, deviceParser = parser.DetectDeviceType(data)
		if deviceType == model.DeviceUnknown {
			return fmt.Errorf("could not auto-detect device type. Use --help to see available device types")
		}
		fmt.Fprintf(os.Stderr, "Auto-detected device type: %s\n", deviceType)
	} else if e.Config.Force || deviceType != "" {
		deviceParser, err = parser.ParserForType(deviceType)
		if err != nil {
			return fmt.Errorf("no parser for device type %s: %w", deviceType, err)
		}
	}

	if deviceParser == nil {
		return fmt.Errorf("no suitable parser found")
	}

	reader := strings.NewReader(string(data))
	device, err := deviceParser.Parse(reader, deviceType)
	if err != nil {
		return fmt.Errorf("parse error: %w", err)
	}

	if e.Config.DeviceName != "" {
		device.DeviceName = e.Config.DeviceName
	}
	if e.Config.Location != "" {
		device.Location = e.Config.Location
	}
	if e.Config.Model != "" {
		device.Model = e.Config.Model
	}

	var result *audit.AuditResult
	if !e.Config.NoAudit {
		result = audit.RunAudit(device, e.Config)
	} else {
		result = &audit.AuditResult{}
	}

	var w io.Writer
	if e.Config.Output == "" || e.Config.Output == "-" {
		w = os.Stdout
	} else {
		f, err := os.Create(e.Config.Output)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		defer f.Close()
		w = f
	}

	reportEngine := report.NewReportEngine(e.Config, device, result)
	if err := reportEngine.Generate(w); err != nil {
		return fmt.Errorf("report generation error: %w", err)
	}

	fmt.Fprintf(os.Stderr, "\nAudit complete: %d findings (%d critical, %d high, %d medium, %d low, %d info)\n",
		result.Summary.Total, result.Summary.Critical, result.Summary.High,
		result.Summary.Medium, result.Summary.Low, result.Summary.Info)

	return nil
}

func ListDevices() {
	for _, p := range parser.All() {
		fmt.Printf("%-20s %s\n", p.Name(), strings.Join(deviceTypesToStrings(p.SupportedTypes()), ", "))
	}
}

func ListFormats() {
	fmt.Println("Available output formats:")
	fmt.Println("  html    HTML report with interactive dark theme (default)")
	fmt.Println("  json    Machine-readable JSON output")
	fmt.Println("  xml     XML report (compatible with nipper)")
	fmt.Println("  text    Plain text report")
	fmt.Println("  latex   LaTeX document for PDF generation")
	fmt.Println("  csv     CSV export of ACL findings")
}

func deviceTypesToStrings(types []model.DeviceType) []string {
	result := make([]string, len(types))
	for i, t := range types {
		result[i] = string(t)
	}
	return result
}
