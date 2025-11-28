package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/timastras9/endpoint/pkg/agent"
	"github.com/timastras9/endpoint/pkg/llm"
	"github.com/timastras9/endpoint/pkg/tools"
)

var (
	targets     []string
	instruction string
	runName     string
	noSandbox   bool
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "endpoint",
		Short: "AI-powered penetration testing",
		Run:   run,
	}

	rootCmd.Flags().StringArrayVarP(&targets, "target", "t", nil, "Target URLs/IPs")
	rootCmd.Flags().StringVarP(&instruction, "instruction", "i", "", "Custom instructions")
	rootCmd.Flags().StringVarP(&runName, "run-name", "n", "", "Scan name")
	rootCmd.Flags().BoolVar(&noSandbox, "no-sandbox", false, "Run without Docker sandbox")

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func run(cmd *cobra.Command, args []string) {
	// Validate environment
	if os.Getenv("ENDPOINT_LLM") == "" {
		color.Red("Error: ENDPOINT_LLM environment variable required")
		os.Exit(1)
	}

	if len(targets) == 0 {
		color.Red("Error: At least one target required (-t)")
		os.Exit(1)
	}

	// Setup context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		color.Yellow("\nShutting down...")
		cancel()
	}()

	// Create LLM client
	config := llm.NewConfigFromEnv()
	llmClient := llm.NewClient(config)

	// Build system prompt
	systemPrompt := buildSystemPrompt()

	// Create and run agent
	a := agent.New("EndpointAgent", llmClient, systemPrompt)
	a.NoSandbox = noSandbox

	task := buildTask(targets, instruction)
	color.Cyan("Starting scan of %d target(s)...\n", len(targets))

	result, err := a.Run(ctx, task)
	if err != nil {
		log.Fatalf("Scan failed: %v", err)
	}

	color.Green("\n=== Scan Complete ===\n")
	fmt.Println(result)
}

func buildSystemPrompt() string {
	return `You are Endpoint, an AI security testing agent. You MUST use tools to perform actions.

` + tools.GetPrompt() + `

IMPORTANT: You MUST call tools using this exact XML format:
<function name="tool_name">
<parameter_name>value</parameter_name>
</function>

Example - port scan:
<function name="port_scan">
<target>example.com</target>
</function>

Example - run a command:
<function name="terminal_execute">
<command>curl -I https://example.com</command>
</function>

Example - report a vulnerability:
<function name="report_vulnerability">
<title>Missing Strict-Transport-Security Header</title>
<severity>high</severity>
<description>The server does not set HSTS header, making it vulnerable to MITM attacks.</description>
<url>https://example.com</url>
</function>

Example - finish scan:
<function name="finish_scan">
<summary>Scan complete. Found 5 vulnerabilities: 1 high, 2 medium, 2 low.</summary>
</function>

CRITICAL RULES - VIOLATION = FAILURE:
1. NEVER call report_vulnerability with the same title twice - if you already reported it, SKIP IT
2. NEVER repeat a command you already ran - check your conversation history
3. TRACK what you have reported - maintain a mental list of reported vulnerabilities
4. Call finish_scan IMMEDIATELY after reporting all unique vulnerabilities
5. Maximum 20 iterations - if you haven't finished by then, call finish_scan anyway
6. Always call exactly ONE tool per response

SCAN SEQUENCE:
1. port_scan the target first
2. Run specialized scans: ssl_scan, dir_scan, cors_scan, cookie_scan, http_methods_scan
3. curl -I for HTTP headers (only once per protocol)
4. Report UNIQUE vulnerabilities only - check if you already reported before calling report_vulnerability
5. Call finish_scan with summary

IMPORTANT DEDUPLICATION:
- Same finding from different tools = ONE vulnerability (e.g., dir_scan finds .git + ssl_scan finds issues = 2 different vulns)
- Same finding from same tool reported twice = VIOLATION - never do this
- If dir_scan found 10 issues, you can report them all ONCE each, but NEVER report the same one twice
- Before each report_vulnerability call, ask yourself: "Did I already report this exact title?" If yes, skip it.

SEVERITY LEVELS:
- critical: exposed source code (.git), exposed credentials, RCE, SQLi
- high: HSTS missing, exposed config files, admin panels, database dumps
- medium: clickjacking, missing CSP, CORS issues
- low: info disclosure, missing optional headers
- info: version disclosure, fingerprinting

EFFICIENCY: Be methodical. Report each finding ONCE. Call finish_scan promptly. Do NOT loop.`
}

func buildTask(targets []string, instruction string) string {
	task := "Perform security testing on:\n"
	for _, t := range targets {
		task += fmt.Sprintf("- %s\n", t)
	}
	if instruction != "" {
		task += "\nInstructions: " + instruction
	}
	return task
}
