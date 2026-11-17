package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"nuclei-mcp/pkg/scanner"
	"nuclei-mcp/pkg/scope"
	"nuclei-mcp/pkg/templates"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func NewNucleiMCPServer(service scanner.ScannerServiceInterface, logger *log.Logger, tm templates.TemplateManager) *server.MCPServer {
	mcpServer := server.NewMCPServer(
		"nuclei-scanner",
		"1.0.0",
		server.WithLogging(),
	)

	mcpServer.AddTool(mcp.NewTool("nuclei_scan",
		mcp.WithDescription("Performs a Nuclei vulnerability scan on a target"),
		mcp.WithString("target",
			mcp.Description("Target URL or IP to scan"),
			mcp.Required(),
		),
		mcp.WithString("severity",
			mcp.Description("Optional severity filter (info, low, medium, high, critical). Leave empty to run templates of ALL severities (needed for CVE/vulnerability templates)."),
		),
		mcp.WithString("protocols",
			mcp.Description("Protocols to scan (comma-separated: http,https,tcp,etc)"),
			mcp.DefaultString("http"),
		),
		mcp.WithString("template_ids",
			mcp.Description("Comma-separated template IDs to run (e.g. \"self-signed-ssl,nameserver-fingerprint\")"),
		),
		mcp.WithString("template_id",
			mcp.Description("Single template ID to run (alternative to template_ids)"),
		),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return HandleNucleiScanTool(ctx, request, service, logger)
	})

	mcpServer.AddTool(mcp.NewTool("basic_scan",
		mcp.WithDescription("Performs a basic Nuclei vulnerability scan on a target without requiring template IDs"),
		mcp.WithString("target",
			mcp.Description("Target URL or IP to scan"),
			mcp.Required(),
		),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return HandleBasicScanTool(ctx, request, service, logger)
	})

	// Add vulnerability resource here
	mcpServer.AddResource(mcp.NewResource("vulnerabilities", "Recent Vulnerability Reports"),
		func(ctx context.Context, request mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
			return HandleVulnerabilityResource(ctx, request, service, logger)
		})

	mcpServer.AddTool(mcp.NewTool("add_template",
		mcp.WithDescription("Adds a new Nuclei template."),
		mcp.WithString("name", mcp.Description("The name of the template file."), mcp.Required()),
		mcp.WithString("content", mcp.Description("The content of the template file."), mcp.Required()),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return HandleAddTemplate(ctx, request, tm)
	})

	mcpServer.AddTool(mcp.NewTool("list_templates",
		mcp.WithDescription("Lists all available Nuclei templates."),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return HandleListTemplates(ctx, request, tm)
	})

	mcpServer.AddTool(mcp.NewTool("get_template",
		mcp.WithDescription("Gets the content of a specific Nuclei template."),
		mcp.WithString("name", mcp.Description("The name of the template file."), mcp.Required()),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return HandleGetTemplate(ctx, request, tm)
	})

	mcpServer.AddTool(mcp.NewTool("nuclei_scope",
		mcp.WithDescription("Lists the allowed target networks (scope). Scans against targets outside this scope are rejected."),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return mcp.NewToolResultText(fmt.Sprintf("Erlaubter Pruefumfang (nur diese Netze werden gescannt):\n- %s", strings.Join(scope.Describe(), "\n- "))), nil
	})

	return mcpServer
}

// sanitizeProtocols bereinigt die Protokoll-Filter fuer die nuclei-SDK.
// "https" ist kein eigener nuclei-Protokolltyp (es faellt unter "http"); ungueltige
// Werte wuerden den Scan abbrechen. Unbekanntes wird verworfen, Duplikate entfernt.
func sanitizeProtocols(s string) string {
	valid := map[string]bool{
		"dns": true, "file": true, "http": true, "headless": true, "network": true,
		"ssl": true, "websocket": true, "whois": true, "code": true, "javascript": true,
		"tcp": true, "udp": true,
	}
	seen := map[string]bool{}
	var out []string
	for _, tok := range strings.Split(s, ",") {
		tok = strings.ToLower(strings.TrimSpace(tok))
		if tok == "https" {
			tok = "http"
		}
		if tok == "" || !valid[tok] || seen[tok] {
			continue
		}
		seen[tok] = true
		out = append(out, tok)
	}
	return strings.Join(out, ",")
}

func HandleNucleiScanTool(
	ctx context.Context,
	request mcp.CallToolRequest,
	service scanner.ScannerServiceInterface,
	_ *log.Logger,
) (*mcp.CallToolResult, error) {
	argMap, ok := request.Params.Arguments.(map[string]any)
	if !ok || argMap == nil {
		return nil, fmt.Errorf("invalid arguments format")
	}

	targetVal, exists := argMap["target"]
	if !exists || targetVal == nil {
		return nil, fmt.Errorf("missing target parameter")
	}
	target, ok := targetVal.(string)
	if !ok || target == "" {
		return nil, fmt.Errorf("invalid target parameter: must be a non-empty string")
	}

	if ok, reason := scope.TargetAllowed(target); !ok {
		return mcp.NewToolResultError(fmt.Sprintf("ABGELEHNT: %s. Erlaubter Pruefumfang: %s", reason, strings.Join(scope.Describe(), ", "))), nil
	}

	// Leer = kein Severity-Filter (alle Schweregrade). Ein fester "info"-Default
	// wuerde CVE-/Schwachstellen-Templates (high/critical) stillschweigend wegfiltern.
	severity := ""
	if severityVal, exists := argMap["severity"]; exists && severityVal != nil {
		if s, ok := severityVal.(string); ok && s != "" {
			severity = s
		}
	}

	protocols := ""
	if protocolsVal, exists := argMap["protocols"]; exists && protocolsVal != nil {
		if p, ok := protocolsVal.(string); ok && p != "" {
			protocols = p
		}
	}
	protocols = sanitizeProtocols(protocols)

	var templateIDs []string
	if idsVal, exists := argMap["template_ids"]; exists && idsVal != nil {
		if ids, ok := idsVal.(string); ok && ids != "" {
			templateIDs = strings.Split(ids, ",")
		}
	}

	if idVal, exists := argMap["template_id"]; exists && idVal != nil {
		if id, ok := idVal.(string); ok && id != "" {
			templateIDs = append(templateIDs, id)
		}
	}

	// Immer der sondierende Scan-Pfad: adressiert auch nackte IPs/Hosts fuer
	// HTTP-Templates korrekt. (Der thread-safe-Pfad sondierte nicht -> Fehltreffer.)
	result, err := service.Scan(target, severity, protocols, templateIDs)
	if err != nil {
		return nil, fmt.Errorf("scan failed: %w", err)
	}

	var responseText string
	if len(result.Findings) == 0 {
		responseText = fmt.Sprintf("No vulnerabilities found for target: %s", target)
	} else {
		responseText = fmt.Sprintf("Found %d vulnerabilities for target: %s\n\n", len(result.Findings), target)

		for i, finding := range result.Findings {
			responseText += fmt.Sprintf("Finding #%d:\n", i+1)
			responseText += fmt.Sprintf("- Name: %s\n", finding.Info.Name)
			if finding.MatcherName != "" {
				responseText += fmt.Sprintf("- Match: %s\n", finding.MatcherName)
			}
			if finding.ExtractorName != "" {
				responseText += fmt.Sprintf("- Extractor: %s\n", finding.ExtractorName)
			}
			responseText += fmt.Sprintf("- Severity: %s\n", finding.Info.SeverityHolder.Severity.String())
			responseText += fmt.Sprintf("- Description: %s\n", finding.Info.Description)
			if len(finding.ExtractedResults) > 0 {
				responseText += fmt.Sprintf("- Extracted: %s\n", strings.Join(finding.ExtractedResults, ", "))
			}
			host := finding.Host
			if finding.Matched != "" {
				host = finding.Matched
			}
			responseText += fmt.Sprintf("- URL: %s\n\n", host)
		}
	}

	return mcp.NewToolResultText(responseText), nil
}

func HandleBasicScanTool(
	_ context.Context,
	request mcp.CallToolRequest,
	service scanner.ScannerServiceInterface,
	logger *log.Logger,
) (*mcp.CallToolResult, error) {
	argMap, ok := request.Params.Arguments.(map[string]any)
	if !ok || argMap == nil {
		return nil, fmt.Errorf("invalid arguments format")
	}

	targetVal, exists := argMap["target"]
	if !exists || targetVal == nil {
		return nil, fmt.Errorf("missing target parameter")
	}
	target, ok := targetVal.(string)
	if !ok || target == "" {
		return nil, fmt.Errorf("invalid target parameter: must be a non-empty string")
	}

	if ok, reason := scope.TargetAllowed(target); !ok {
		return mcp.NewToolResultError(fmt.Sprintf("ABGELEHNT: %s. Erlaubter Pruefumfang: %s", reason, strings.Join(scope.Describe(), ", "))), nil
	}

	result, err := service.BasicScan(target)
	if err != nil {
		logger.Printf("Basic scan failed: %v", err)
		return nil, err
	}

	type SimplifiedFinding struct {
		Name        string   `json:"name"`
		Match       string   `json:"match,omitempty"`
		Severity    string   `json:"severity"`
		Description string   `json:"description"`
		Extracted   []string `json:"extracted,omitempty"`
		URL         string   `json:"url"`
	}

	simplifiedFindings := make([]SimplifiedFinding, 0, len(result.Findings))
	for _, finding := range result.Findings {
		if finding == nil {
			continue
		}

		severity := "unknown"
		if finding.Info.SeverityHolder.Severity.String() != "" {
			severity = finding.Info.SeverityHolder.Severity.String()
		}

		url := finding.Host
		if finding.Matched != "" {
			url = finding.Matched
		}

		simplifiedFindings = append(simplifiedFindings, SimplifiedFinding{
			Name:        finding.Info.Name,
			Match:       finding.MatcherName,
			Severity:    severity,
			Description: finding.Info.Description,
			Extracted:   finding.ExtractedResults,
			URL:         url,
		})
	}

	response := map[string]interface{}{
		"target":         result.Target,
		"scan_time":      result.ScanTime.Format(time.RFC3339),
		"findings_count": len(result.Findings),
		"findings":       simplifiedFindings,
	}

	responseJSON, err := json.Marshal(response)
	if err != nil {
		logger.Printf("Failed to marshal response: %v", err)
		return nil, err
	}

	return mcp.NewToolResultText(string(responseJSON)), nil
}

func HandleVulnerabilityResource(
	_ context.Context,
	_ mcp.ReadResourceRequest,
	service scanner.ScannerServiceInterface,
	_ *log.Logger,
) ([]mcp.ResourceContents, error) {
	results := service.GetAll()

	var recentScans []map[string]interface{}
	for _, result := range results {
		scanInfo := map[string]interface{}{
			"target":    result.Target,
			"scan_time": result.ScanTime.Format(time.RFC3339),
			"findings":  len(result.Findings),
		}

		if len(result.Findings) > 0 {
			var sampleFindings []map[string]string

			count := min(5, len(result.Findings))
			for i := 0; i < count; i++ {
				finding := result.Findings[i]
				if finding == nil {
					continue
				}

				severity := "unknown"
				if finding.Info.SeverityHolder.Severity.String() != "" {
					severity = finding.Info.SeverityHolder.Severity.String()
				}

				sampleFindings = append(sampleFindings, map[string]string{
					"name":        finding.Info.Name,
					"severity":    severity,
					"description": finding.Info.Description,
					"url":         finding.Host,
				})
			}
			scanInfo["sample_findings"] = sampleFindings
		}

		recentScans = append(recentScans, scanInfo)
	}

	report := map[string]interface{}{
		"timestamp":    time.Now().Format(time.RFC3339),
		"recent_scans": recentScans,
		"total_scans":  len(recentScans),
	}

	reportJSON, err := json.Marshal(report)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal report: %w", err)
	}

	return []mcp.ResourceContents{
			mcp.TextResourceContents{
				URI:      "vulnerabilities",
				MIMEType: "application/json",
				Text:     string(reportJSON),
			},
		},
		nil
}

func min(x, y int) int {
	if x < y {
		return x
	}
	return y
}

func HandleAddTemplate(_ context.Context, request mcp.CallToolRequest, tm templates.TemplateManager) (*mcp.CallToolResult, error) {
	argMap, ok := request.Params.Arguments.(map[string]any)
	if !ok || argMap == nil {
		return nil, fmt.Errorf("invalid arguments format")
	}

	nameVal, exists := argMap["name"]
	if !exists || nameVal == nil {
		return nil, fmt.Errorf("missing name parameter")
	}
	name, ok := nameVal.(string)
	if !ok || name == "" {
		return nil, fmt.Errorf("invalid name parameter: must be a non-empty string")
	}

	contentVal, exists := argMap["content"]
	if !exists || contentVal == nil {
		return nil, fmt.Errorf("missing content parameter")
	}
	content, ok := contentVal.(string)
	if !ok || content == "" {
		return nil, fmt.Errorf("invalid content parameter: must be a non-empty string")
	}

	if err := tm.AddTemplate(name, []byte(content)); err != nil {
		return nil, fmt.Errorf("failed to add template: %w", err)
	}

	return mcp.NewToolResultText(fmt.Sprintf("Template '%s' added successfully.", name)), nil
}

func HandleListTemplates(_ context.Context, _ mcp.CallToolRequest, tm templates.TemplateManager) (*mcp.CallToolResult, error) {
	templateFiles, err := tm.ListTemplates()
	if err != nil {
		return nil, fmt.Errorf("failed to list templates: %w", err)
	}

	if len(templateFiles) == 0 {
		return mcp.NewToolResultText("No custom templates found."), nil
	}

	return mcp.NewToolResultText(fmt.Sprintf("Available templates:\n- %s", strings.Join(templateFiles, "\n- "))), nil
}

func HandleGetTemplate(_ context.Context, request mcp.CallToolRequest, tm templates.TemplateManager) (*mcp.CallToolResult, error) {
	argMap, ok := request.Params.Arguments.(map[string]any)
	if !ok || argMap == nil {
		return nil, fmt.Errorf("invalid arguments format")
	}

	nameVal, exists := argMap["name"]
	if !exists || nameVal == nil {
		return nil, fmt.Errorf("missing name parameter")
	}
	name, ok := nameVal.(string)
	if !ok || name == "" {
		return nil, fmt.Errorf("invalid name parameter: must be a non-empty string")
	}

	content, err := tm.GetTemplate(name)
	if err != nil {
		return nil, fmt.Errorf("failed to get template: %w", err)
	}

	return mcp.NewToolResultText(string(content)), nil
}
