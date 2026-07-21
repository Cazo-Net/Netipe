package report

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"strings"
	"text/template"
	"time"

	"github.com/Cazo-Net/netpipe/internal/audit"
	"github.com/Cazo-Net/netpipe/internal/config"
	"github.com/Cazo-Net/netpipe/internal/model"
)

type ReportData struct {
	Title       string
	DeviceName  string
	DeviceType  string
	Version     string
	Model       string
	GeneratedAt time.Time
	CompanyName string
	Findings    []audit.Finding
	Summary     audit.AuditSummary
	Device      *model.DeviceConfig
	Sections    []ReportSection
}

type ReportSection struct {
	Title    string
	Content  string
	Level    int
}

type ReportEngine struct {
	cfg    *config.Config
	device *model.DeviceConfig
	result *audit.AuditResult
}

func NewReportEngine(cfg *config.Config, device *model.DeviceConfig, result *audit.AuditResult) *ReportEngine {
	return &ReportEngine{
		cfg:    cfg,
		device: device,
		result: result,
	}
}

func (r *ReportEngine) Generate(w io.Writer) error {
	data := r.buildReportData()

	switch r.cfg.OutputFormat {
	case "json":
		return r.generateJSON(w, data)
	case "xml":
		return r.generateXML(w, data)
	case "html":
		return r.generateHTML(w, data)
	case "text":
		return r.generateText(w, data)
	case "latex":
		return r.generateLaTeX(w, data)
	case "csv":
		return r.generateCSV(w, data)
	default:
		return r.generateHTML(w, data)
	}
}

func (r *ReportEngine) buildReportData() *ReportData {
	data := &ReportData{
		Title:       fmt.Sprintf("Security Audit Report - %s", r.device.Hostname),
		DeviceName:  r.device.DeviceName,
		DeviceType:  string(r.device.DeviceType),
		Version:     r.device.Version,
		Model:       r.device.Model,
		GeneratedAt: time.Now(),
		CompanyName: r.cfg.CompanyName,
		Device:      r.device,
	}

	if r.result != nil {
		data.Findings = r.result.Findings
		data.Summary = r.result.Summary
	}

	return data
}

func (r *ReportEngine) generateJSON(w io.Writer, data *ReportData) error {
	output := struct {
		Title       string           `json:"title"`
		Device      *model.DeviceConfig `json:"device"`
		Summary     audit.AuditSummary  `json:"summary"`
		Findings    []audit.Finding     `json:"findings"`
		GeneratedAt string              `json:"generated_at"`
		Tool        string              `json:"tool"`
		Version     string              `json:"version"`
	}{
		Title:       data.Title,
		Device:      data.Device,
		Summary:     data.Summary,
		Findings:    data.Findings,
		GeneratedAt: data.GeneratedAt.Format(time.RFC3339),
		Tool:        "NetPipe",
		Version:     "1.0.0",
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(output)
}

func (r *ReportEngine) generateXML(w io.Writer, data *ReportData) error {
	fmt.Fprintln(w, `<?xml version="1.0" encoding="UTF-8"?>`)
	fmt.Fprintln(w, `<netpipe-report>`)

	xmlEncoder := xml.NewEncoder(w)
	xmlEncoder.Indent("", "  ")

	type xmlReport struct {
		XMLName     xml.Name         `xml:"report"`
		Title       string           `xml:"title"`
		DeviceType  string           `xml:"device-type"`
		Version     string           `xml:"version"`
		Model       string           `xml:"model"`
		GeneratedAt string           `xml:"generated-at"`
		CompanyName string           `xml:"company-name"`
		Summary     struct {
			Critical int `xml:"critical"`
			High     int `xml:"high"`
			Medium   int `xml:"medium"`
			Low      int `xml:"low"`
			Info     int `xml:"informational"`
			Total    int `xml:"total"`
		} `xml:"summary"`
		Findings []struct {
			ID              string `xml:"id"`
			Title           string `xml:"title"`
			Description     string `xml:"description"`
			Impact          string `xml:"impact"`
			Recommendation  string `xml:"recommendation"`
			Severity        string `xml:"severity"`
			Category        string `xml:"category"`
			FixCommand      string `xml:"fix-command,omitempty"`
			Reference       string `xml:"reference,omitempty"`
			CVE             string `xml:"cve,omitempty"`
		} `xml:"finding"`
	}

	xmlData := xmlReport{
		Title:       data.Title,
		DeviceType:  data.DeviceType,
		Version:     data.Version,
		Model:       data.Model,
		GeneratedAt: data.GeneratedAt.Format(time.RFC3339),
		CompanyName: data.CompanyName,
	}
	xmlData.Summary.Critical = data.Summary.Critical
	xmlData.Summary.High = data.Summary.High
	xmlData.Summary.Medium = data.Summary.Medium
	xmlData.Summary.Low = data.Summary.Low
	xmlData.Summary.Info = data.Summary.Info
	xmlData.Summary.Total = data.Summary.Total

	for _, f := range data.Findings {
		xmlData.Findings = append(xmlData.Findings, struct {
			ID              string `xml:"id"`
			Title           string `xml:"title"`
			Description     string `xml:"description"`
			Impact          string `xml:"impact"`
			Recommendation  string `xml:"recommendation"`
			Severity        string `xml:"severity"`
			Category        string `xml:"category"`
			FixCommand      string `xml:"fix-command,omitempty"`
			Reference       string `xml:"reference,omitempty"`
			CVE             string `xml:"cve,omitempty"`
		}{
			ID:              f.ID,
			Title:           f.Title,
			Description:     f.Description,
			Impact:          f.Impact,
			Recommendation:  f.Recommendation,
			Severity:        string(f.Severity),
			Category:        f.Category,
			FixCommand:      f.FixCommand,
			Reference:       f.Reference,
			CVE:             f.CVE,
		})
	}

	xmlEncoder.Encode(xmlData)
	fmt.Fprintln(w)
	fmt.Fprintln(w, `</netpipe-report>`)
	return nil
}

func (r *ReportEngine) generateText(w io.Writer, data *ReportData) error {
	fmt.Fprintln(w, strings.Repeat("=", 72))
	fmt.Fprintf(w, "  NETPIPE SECURITY AUDIT REPORT\n")
	fmt.Fprintln(w, strings.Repeat("=", 72))
	fmt.Fprintf(w, "\nDevice:     %s\n", data.Device.Hostname)
	fmt.Fprintf(w, "Type:       %s\n", data.DeviceType)
	fmt.Fprintf(w, "Version:    %s\n", data.Version)
	fmt.Fprintf(w, "Model:      %s\n", data.Model)
	fmt.Fprintf(w, "Generated:  %s\n", data.GeneratedAt.Format("2006-01-02 15:04:05"))
	fmt.Fprintf(w, "Tool:       NetPipe v1.0.0\n")

	fmt.Fprintln(w, "\n"+strings.Repeat("-", 72))
	fmt.Fprintln(w, "EXECUTIVE SUMMARY")
	fmt.Fprintln(w, strings.Repeat("-", 72))
	fmt.Fprintf(w, "Critical:   %d\n", data.Summary.Critical)
	fmt.Fprintf(w, "High:       %d\n", data.Summary.High)
	fmt.Fprintf(w, "Medium:     %d\n", data.Summary.Medium)
	fmt.Fprintf(w, "Low:        %d\n", data.Summary.Low)
	fmt.Fprintf(w, "Info:       %d\n", data.Summary.Info)
	fmt.Fprintf(w, "Total:      %d\n", data.Summary.Total)

	if len(data.Findings) > 0 {
		fmt.Fprintln(w, "\n"+strings.Repeat("-", 72))
		fmt.Fprintln(w, "SECURITY FINDINGS")
		fmt.Fprintln(w, strings.Repeat("-", 72))

		for i, f := range data.Findings {
			fmt.Fprintf(w, "\n[Finding %d] %s (%s)\n", i+1, f.Title, strings.ToUpper(string(f.Severity)))
			fmt.Fprintf(w, "ID:          %s\n", f.ID)
			fmt.Fprintf(w, "Category:    %s\n", f.Category)
			fmt.Fprintf(w, "Description: %s\n", f.Description)
			if f.Impact != "" {
				fmt.Fprintf(w, "Impact:      %s\n", f.Impact)
			}
			if f.Recommendation != "" {
				fmt.Fprintf(w, "Recommend:   %s\n", f.Recommendation)
			}
			if f.FixCommand != "" {
				fmt.Fprintf(w, "Fix:\n")
				for _, line := range strings.Split(f.FixCommand, "\n") {
					fmt.Fprintf(w, "  %s\n", line)
				}
			}
			if f.Reference != "" {
				fmt.Fprintf(w, "Reference:   %s\n", f.Reference)
			}
			fmt.Fprintln(w, strings.Repeat(".", 72))
		}
	}

	fmt.Fprintln(w, "\n"+strings.Repeat("=", 72))
	fmt.Fprintln(w, "END OF REPORT")
	fmt.Fprintln(w, strings.Repeat("=", 72))
	return nil
}

func (r *ReportEngine) generateLaTeX(w io.Writer, data *ReportData) error {
	fmt.Fprintf(w, "\\documentclass{%s}\n", r.cfg.DocumentClass)
	if r.cfg.DocumentClass == "" {
		fmt.Fprintln(w, "\\documentclass{article}")
	}
	fmt.Fprintln(w, "\\usepackage[utf8]{inputenc}")
	fmt.Fprintln(w, "\\usepackage{longtable}")
	fmt.Fprintln(w, "\\usepackage{booktabs}")
	fmt.Fprintln(w, "\\usepackage{hyperref}")
	fmt.Fprintln(w, "\\usepackage{xcolor}")
	fmt.Fprintln(w, "\\usepackage{geometry}")
	fmt.Fprintln(w, "\\geometry{margin=1in}")
	fmt.Fprintln(w)

	fmt.Fprintf(w, "\\title{%s}\n", escapeLaTeX(data.Title))
	fmt.Fprintf(w, "\\author{NetPipe v1.0.0}\n")
	fmt.Fprintf(w, "\\date{%s}\n", data.GeneratedAt.Format("January 2, 2006"))
	fmt.Fprintln(w, "\\begin{document}")
	fmt.Fprintln(w, "\\maketitle")

	fmt.Fprintln(w, "\\section{Executive Summary}")
	fmt.Fprintln(w, "\\begin{itemize}")
	fmt.Fprintf(w, "\\item Device: %s (%s)\n", escapeLaTeX(data.Device.Hostname), escapeLaTeX(data.DeviceType))
	fmt.Fprintf(w, "\\item Version: %s\n", escapeLaTeX(data.Version))
	fmt.Fprintf(w, "\\item Critical Findings: %d\n", data.Summary.Critical)
	fmt.Fprintf(w, "\\item High Findings: %d\n", data.Summary.High)
	fmt.Fprintf(w, "\\item Medium Findings: %d\n", data.Summary.Medium)
	fmt.Fprintf(w, "\\item Low Findings: %d\n", data.Summary.Low)
	fmt.Fprintf(w, "\\item Informational: %d\n", data.Summary.Info)
	fmt.Fprintln(w, "\\end{itemize}")

	if len(data.Findings) > 0 {
		fmt.Fprintln(w, "\\section{Security Findings}")
		fmt.Fprintln(w, "\\begin{longtable}{|l|l|l|p{8cm}|}")
		fmt.Fprintln(w, "\\hline")
		fmt.Fprintln(w, "\\textbf{ID} & \\textbf{Severity} & \\textbf{Category} & \\textbf{Title} \\\\")
		fmt.Fprintln(w, "\\hline")

		for _, f := range data.Findings {
			color := "green"
			switch f.Severity {
			case model.SeverityCritical:
				color = "red"
			case model.SeverityHigh:
				color = "orange"
			case model.SeverityMedium:
				color = "yellow"
			}
			fmt.Fprintf(w, "%s & \\textcolor{%s}{%s} & %s & %s \\\\\n",
				escapeLaTeX(f.ID), color, strings.ToUpper(string(f.Severity)),
				escapeLaTeX(f.Category), escapeLaTeX(f.Title))
			fmt.Fprintln(w, "\\hline")
		}
		fmt.Fprintln(w, "\\end{longtable}")

		fmt.Fprintln(w, "\\section{Detailed Findings}")
		for i, f := range data.Findings {
			fmt.Fprintf(w, "\\subsection{[%s] %s}\n", escapeLaTeX(f.ID), escapeLaTeX(f.Title))
			fmt.Fprintf(w, "\\textbf{Severity:} %s \\\\\n", strings.ToUpper(string(f.Severity)))
			fmt.Fprintf(w, "\\textbf{Category:} %s \\\\\n", escapeLaTeX(f.Category))
			fmt.Fprintf(w, "\\textbf{Description:} %s \\\\\n\n", escapeLaTeX(f.Description))
			if f.Impact != "" {
				fmt.Fprintf(w, "\\textbf{Impact:} %s \\\\\n\n", escapeLaTeX(f.Impact))
			}
			if f.Recommendation != "" {
				fmt.Fprintf(w, "\\textbf{Recommendation:} %s \\\\\n\n", escapeLaTeX(f.Recommendation))
			}
			if f.FixCommand != "" {
				fmt.Fprintf(w, "\\textbf{Fix Command:}\n\\begin{verbatim}\n%s\n\\end{verbatim}\n\n", f.FixCommand)
			}
			if i < len(data.Findings)-1 {
				fmt.Fprintln(w, "\\newpage")
			}
		}
	}

	fmt.Fprintln(w, "\\end{document}")
	return nil
}

func (r *ReportEngine) generateCSV(w io.Writer, data *ReportData) error {
	fmt.Fprintln(w, "ID,Title,Severity,Category,Description,Impact,Recommendation,FixCommand,Reference,CVE")
	for _, f := range data.Findings {
		fmt.Fprintf(w, "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n",
			csvEscape(f.ID),
			csvEscape(f.Title),
			csvEscape(string(f.Severity)),
			csvEscape(f.Category),
			csvEscape(f.Description),
			csvEscape(f.Impact),
			csvEscape(f.Recommendation),
			csvEscape(f.FixCommand),
			csvEscape(f.Reference),
			csvEscape(f.CVE),
		)
	}
	return nil
}

func (r *ReportEngine) generateHTML(w io.Writer, data *ReportData) error {
	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"severityColor": func(s model.Severity) string {
			switch s {
			case model.SeverityCritical:
				return "#dc3545"
			case model.SeverityHigh:
				return "#fd7e14"
			case model.SeverityMedium:
				return "#ffc107"
			case model.SeverityLow:
				return "#28a745"
			default:
				return "#17a2b8"
			}
		},
		"severityBg": func(s model.Severity) string {
			switch s {
			case model.SeverityCritical:
				return "#f8d7da"
			case model.SeverityHigh:
				return "#fff3cd"
			case model.SeverityMedium:
				return "#fff3cd"
			case model.SeverityLow:
				return "#d4edda"
			default:
				return "#d1ecf1"
			}
		},
	"upper": strings.ToUpper,
	"stringify": func(s model.Severity) string {
		return string(s)
	},
	"nl2br": func(s string) string {
			return strings.ReplaceAll(s, "\n", "<br>")
		},
	}).Parse(htmlTemplate)
	if err != nil {
		return err
	}

	return tmpl.Execute(w, data)
}

func csvEscape(s string) string {
	s = strings.ReplaceAll(s, `"`, `""`)
	if strings.ContainsAny(s, ",\"\n\r") {
		return `"` + s + `"`
	}
	return s
}

func escapeLaTeX(s string) string {
	s = strings.ReplaceAll(s, `\`, `\textbackslash{}`)
	s = strings.ReplaceAll(s, "&", `\&`)
	s = strings.ReplaceAll(s, `%`, `\%`)
	s = strings.ReplaceAll(s, `$`, `\$`)
	s = strings.ReplaceAll(s, `#`, `\#`)
	s = strings.ReplaceAll(s, `_`, `\_`)
	s = strings.ReplaceAll(s, `{`, `\{`)
	s = strings.ReplaceAll(s, `}`, `\}`)
	s = strings.ReplaceAll(s, `~`, `\textasciitilde{}`)
	s = strings.ReplaceAll(s, `^`, `\textasciicircum{}`)
	return s
}

var htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{.Title}}</title>
    <style>
        :root {
            --bg: #1a1a2e;
            --surface: #16213e;
            --surface2: #0f3460;
            --text: #e6e6e6;
            --text-muted: #a0a0b0;
            --accent: #0f3460;
            --critical: #dc3545;
            --high: #fd7e14;
            --medium: #ffc107;
            --low: #28a745;
            --info: #17a2b8;
            --border: #2a2a4a;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background: var(--bg);
            color: var(--text);
            line-height: 1.6;
            padding: 2rem;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        header {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 2rem;
            margin-bottom: 2rem;
            text-align: center;
        }
        header h1 { font-size: 2rem; margin-bottom: 0.5rem; color: #fff; }
        header .meta { color: var(--text-muted); font-size: 0.9rem; }
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }
        .summary-card {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 1.5rem;
            text-align: center;
        }
        .summary-card .number {
            font-size: 2.5rem;
            font-weight: 700;
            display: block;
        }
        .summary-card .label {
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.1em;
            color: var(--text-muted);
        }
        .summary-card.critical .number { color: var(--critical); }
        .summary-card.high .number { color: var(--high); }
        .summary-card.medium .number { color: var(--medium); }
        .summary-card.low .number { color: var(--low); }
        .summary-card.info .number { color: var(--info); }
        .summary-card.total .number { color: #fff; }
        .findings { margin-top: 2rem; }
        .finding {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 10px;
            margin-bottom: 1rem;
            overflow: hidden;
        }
        .finding-header {
            padding: 1rem 1.5rem;
            display: flex;
            align-items: center;
            gap: 1rem;
            cursor: pointer;
        }
        .finding-header:hover { background: var(--surface2); }
        .severity-badge {
            padding: 0.25rem 0.75rem;
            border-radius: 6px;
            font-size: 0.75rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            white-space: nowrap;
        }
        .finding-id {
            font-family: 'Fira Code', 'Cascadia Code', monospace;
            color: var(--text-muted);
            font-size: 0.85rem;
        }
        .finding-title { font-weight: 600; flex: 1; }
        .finding-body {
            padding: 0 1.5rem 1.5rem;
            display: none;
        }
        .finding.open .finding-body { display: block; }
        .finding-body h4 {
            color: var(--text-muted);
            font-size: 0.8rem;
            text-transform: uppercase;
            letter-spacing: 0.1em;
            margin-top: 1rem;
            margin-bottom: 0.5rem;
        }
        .finding-body p { color: var(--text); margin-bottom: 0.5rem; }
        .fix-cmd {
            background: #0d1117;
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 1rem;
            font-family: 'Fira Code', 'Cascadia Code', monospace;
            font-size: 0.85rem;
            overflow-x: auto;
            white-space: pre-wrap;
        }
        .device-info {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 1.5rem;
            margin-bottom: 2rem;
        }
        .device-info h2 {
            font-size: 1.2rem;
            margin-bottom: 1rem;
            color: var(--text-muted);
        }
        .device-info table { width: 100%; }
        .device-info td {
            padding: 0.5rem;
            border-bottom: 1px solid var(--border);
        }
        .device-info td:first-child {
            color: var(--text-muted);
            width: 200px;
        }
        footer {
            text-align: center;
            margin-top: 3rem;
            padding: 2rem;
            color: var(--text-muted);
            font-size: 0.85rem;
        }
        @media (max-width: 768px) {
            body { padding: 1rem; }
            .summary-grid { grid-template-columns: repeat(3, 1fr); }
            .finding-header { flex-wrap: wrap; }
        }
        @media print {
            :root {
                --bg: #fff;
                --surface: #fff;
                --surface2: #f8f9fa;
                --text: #212529;
                --text-muted: #6c757d;
                --border: #dee2e6;
            }
            .finding-body { display: block !important; }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>NetPipe Security Audit Report</h1>
            <div class="meta">
                Generated: {{.GeneratedAt.Format "January 2, 2006 15:04:05"}} |
                Tool: NetPipe v1.0.0 |
                Device: {{.Device.Hostname}}
            </div>
        </header>

        <div class="device-info">
            <h2>Device Information</h2>
            <table>
                <tr><td>Hostname</td><td>{{.Device.Hostname}}</td></tr>
                <tr><td>Device Type</td><td>{{.DeviceType}}</td></tr>
                <tr><td>Version</td><td>{{.Version}}</td></tr>
                <tr><td>Model</td><td>{{.Model}}</td></tr>
                <tr><td>Interfaces</td><td>{{len .Device.Interfaces}}</td></tr>
                <tr><td>ACLs</td><td>{{len .Device.ACLs}}</td></tr>
                <tr><td>Users</td><td>{{len .Device.Users}}</td></tr>
            </table>
        </div>

        <div class="summary-grid">
            <div class="summary-card critical">
                <span class="number">{{.Summary.Critical}}</span>
                <span class="label">Critical</span>
            </div>
            <div class="summary-card high">
                <span class="number">{{.Summary.High}}</span>
                <span class="label">High</span>
            </div>
            <div class="summary-card medium">
                <span class="number">{{.Summary.Medium}}</span>
                <span class="label">Medium</span>
            </div>
            <div class="summary-card low">
                <span class="number">{{.Summary.Low}}</span>
                <span class="label">Low</span>
            </div>
            <div class="summary-card info">
                <span class="number">{{.Summary.Info}}</span>
                <span class="label">Info</span>
            </div>
            <div class="summary-card total">
                <span class="number">{{.Summary.Total}}</span>
                <span class="label">Total</span>
            </div>
        </div>

        <div class="findings">
            <h2 style="margin-bottom: 1rem; color: var(--text-muted);">Security Findings</h2>
            {{range .Findings}}
            <div class="finding" onclick="this.classList.toggle('open')">
                <div class="finding-header">
                    <span class="severity-badge" style="background: {{severityColor .Severity}}; color: #fff;">{{upper (stringify .Severity)}}</span>
                    <span class="finding-id">{{.ID}}</span>
                    <span class="finding-title">{{.Title}}</span>
                </div>
                <div class="finding-body">
                    <h4>Category</h4>
                    <p>{{.Category}}</p>
                    <h4>Description</h4>
                    <p>{{.Description}}</p>
                    {{if .Impact}}<h4>Impact</h4><p>{{.Impact}}</p>{{end}}
                    {{if .Recommendation}}<h4>Recommendation</h4><p>{{.Recommendation}}</p>{{end}}
                    {{if .FixCommand}}<h4>Fix Command</h4><div class="fix-cmd">{{.FixCommand}}</div>{{end}}
                    {{if .Reference}}<h4>Reference</h4><p>{{.Reference}}</p>{{end}}
                    {{if .CVE}}<h4>CVE</h4><p>{{.CVE}}</p>{{end}}
                </div>
            </div>
            {{end}}
        </div>

        <footer>
            <p>Report generated by <strong>NetPipe v1.0.0</strong> | Network Infrastructure Configuration Parser and Security Auditor</p>
            <p>Based on nipper-ng by Ian Ventura-Whiting | Licensed under GPL v3</p>
        </footer>
    </div>

    <script>
        document.addEventListener('DOMContentLoaded', function() {
            document.querySelectorAll('.finding').forEach(function(el) {
                el.style.cursor = 'pointer';
            });
        });
    </script>
</body>
</html>`
