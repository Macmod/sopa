package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode"

	adws "github.com/Macmod/sopa"
	"github.com/c-bata/go-prompt"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"golang.org/x/term"
)

// ---------------------------------------------------------------------------
// crlfWriter — wraps an io.Writer, replacing bare \n with \r\n so that output
// works correctly while go-prompt holds the terminal in raw mode.
// ---------------------------------------------------------------------------

type crlfWriter struct{ w io.Writer }

func (cw crlfWriter) Write(p []byte) (int, error) {
	out := make([]byte, 0, len(p)+8)
	for i, b := range p {
		if b == '\n' && (i == 0 || p[i-1] != '\r') {
			out = append(out, '\r')
		}
		out = append(out, b)
	}
	n, err := cw.w.Write(out)
	if n > len(p) {
		n = len(p)
	}
	return n, err
}

// ---------------------------------------------------------------------------
// Completion tables
// ---------------------------------------------------------------------------

var topSuggestions = []prompt.Suggest{
	{Text: "query", Description: "Enumerate objects (WS-Enumeration)"},
	{Text: "get", Description: "Get an object by DN (WS-Transfer Get)"},
	{Text: "attr", Description: "Modify an attribute (WS-Transfer Put)"},
	{Text: "create", Description: "Create AD objects (WS-Transfer Create)"},
	{Text: "delete", Description: "Delete an object (WS-Transfer Delete)"},
	{Text: "set-password", Description: "Set account password (MS-ADCAP SetPassword)"},
	{Text: "change-password", Description: "Change account password (MS-ADCAP ChangePassword)"},
	{Text: "translate-name", Description: "Translate name formats (MS-ADCAP TranslateName)"},
	{Text: "groups", Description: "List groups for a principal"},
	{Text: "members", Description: "List members of a group"},
	{Text: "optfeature", Description: "Enable/disable an optional feature"},
	{Text: "info", Description: "Topology info (MS-ADCAP)"},
	{Text: "mex", Description: "Fetch ADWS metadata (unauthenticated)"},
	{Text: "help", Description: "Show help"},
	{Text: "exit", Description: "Exit the shell"},
}

var attrSubSuggestions = []prompt.Suggest{
	{Text: "add", Description: "Add attribute values"},
	{Text: "replace", Description: "Replace attribute values"},
	{Text: "delete", Description: "Delete attribute values"},
}

var createSubSuggestions = []prompt.Suggest{
	{Text: "computer", Description: "Create a computer account"},
	{Text: "user", Description: "Create a user account"},
	{Text: "group", Description: "Create a group"},
	{Text: "ou", Description: "Create an organizational unit"},
	{Text: "container", Description: "Create a container"},
	{Text: "custom", Description: "Create via YAML template"},
}

var infoSubSuggestions = []prompt.Suggest{
	{Text: "version", Description: "ADWS Custom Action Protocol version"},
	{Text: "domain", Description: "Domain info"},
	{Text: "forest", Description: "Forest info"},
	{Text: "dcs", Description: "Domain controller info"},
}

// flagSuggestions maps a command path (or "cmd sub") to its flags.
var flagSuggestions = map[string][]prompt.Suggest{
	"query": {
		{Text: "--filter", Description: "LDAP filter (default: (objectClass=*))"},
		{Text: "--attrs", Description: "Comma-separated attributes to fetch"},
		{Text: "--scope", Description: "Search scope: 0=Base 1=Onelevel 2=Subtree"},
		{Text: "--max", Description: "Max objects to print (0=all)"},
		{Text: "--json", Description: "Output as NDJSON"},
	},
	"get": {
		{Text: "--dn", Description: "Distinguished Name to get"},
		{Text: "--attrs", Description: "Comma-separated attributes to fetch"},
		{Text: "--json", Description: "Output as NDJSON"},
	},
	"delete": {
		{Text: "--dn", Description: "Distinguished Name to delete"},
		{Text: "--json", Description: "Output as NDJSON"},
	},
	"set-password": {
		{Text: "--dn", Description: "Account distinguished name"},
		{Text: "--new", Description: "New password"},
		{Text: "--partition-dn", Description: "Partition naming context DN"},
		{Text: "--json", Description: "Output as NDJSON"},
	},
	"change-password": {
		{Text: "--dn", Description: "Account distinguished name"},
		{Text: "--old", Description: "Old password"},
		{Text: "--new", Description: "New password"},
		{Text: "--partition-dn", Description: "Partition naming context DN"},
		{Text: "--json", Description: "Output as NDJSON"},
	},
	"translate-name": {
		{Text: "--offered", Description: "Offered format (default: DistinguishedName)"},
		{Text: "--desired", Description: "Desired format (default: CanonicalName)"},
		{Text: "--json", Description: "Output as NDJSON"},
	},
	"groups": {
		{Text: "--dn", Description: "Principal distinguished name"},
		{Text: "--membership", Description: "Show membership groups"},
		{Text: "--authz", Description: "Show authorization groups"},
		{Text: "--json", Description: "Output as NDJSON"},
	},
	"members": {
		{Text: "--dn", Description: "Group distinguished name"},
		{Text: "--partition-dn", Description: "Partition naming context DN (default: derived from --domain)"},
		{Text: "--recursive", Description: "Recursively include child group members"},
		{Text: "--json", Description: "Output as NDJSON"},
	},
	"optfeature": {
		{Text: "--dn", Description: "Naming context DN (default: derived from --domain)"},
		{Text: "--feature-id", Description: "Feature GUID (e.g. Recycle Bin)"},
		{Text: "--enable", Description: "Enable the feature (default: disable)"},
		{Text: "--json", Description: "Output as NDJSON"},
	},
	"mex":  {{Text: "--json", Description: "Output as NDJSON"}},
	"info": {},
	"attr add": {
		{Text: "--dn", Description: "Target distinguished name"},
		{Text: "--attr", Description: "Attribute name"},
		{Text: "--value", Description: "Comma-separated value(s) to add"},
		{Text: "--json", Description: "Output as NDJSON"},
	},
	"attr replace": {
		{Text: "--dn", Description: "Target distinguished name"},
		{Text: "--attr", Description: "Attribute name"},
		{Text: "--value", Description: "Comma-separated value(s) to set"},
		{Text: "--json", Description: "Output as NDJSON"},
	},
	"attr delete": {
		{Text: "--dn", Description: "Target distinguished name"},
		{Text: "--attr", Description: "Attribute name"},
		{Text: "--json", Description: "Output as NDJSON"},
	},
	"create computer": {
		{Text: "--name", Description: "Computer name (e.g. PENTEST or PENTEST$)"},
		{Text: "--pass", Description: "Password for the computer account"},
		{Text: "--parent-dn", Description: "Parent container DN"},
		{Text: "--json", Description: "Output as NDJSON"},
	},
	"create user": {
		{Text: "--name", Description: "Username (CN, max 20 chars)"},
		{Text: "--pass", Description: "Password (optional)"},
		{Text: "--parent-dn", Description: "Parent container DN"},
		{Text: "--enabled", Description: "Enable user (default: true if --pass given)"},
		{Text: "--json", Description: "Output as NDJSON"},
	},
	"create group": {
		{Text: "--name", Description: "Group name (CN)"},
		{Text: "--type", Description: "Group type (e.g. GlobalSecurity)"},
		{Text: "--parent-dn", Description: "Parent container DN"},
		{Text: "--json", Description: "Output as NDJSON"},
	},
	"create ou": {
		{Text: "--name", Description: "OU name"},
		{Text: "--parent-dn", Description: "Parent container DN"},
		{Text: "--json", Description: "Output as NDJSON"},
	},
	"create container": {
		{Text: "--name", Description: "Container name (CN)"},
		{Text: "--parent-dn", Description: "Parent container DN"},
		{Text: "--json", Description: "Output as NDJSON"},
	},
	"create custom": {
		{Text: "--file", Description: "Path to YAML template file"},
		{Text: "--json", Description: "Output as NDJSON"},
	},
	"info dcs": {
		{Text: "--ntds-dn", Description: "nTDSDSA DN (repeatable; auto-discovers if omitted)"},
		{Text: "--json", Description: "Output as NDJSON"},
	},
	"info version": {{Text: "--json", Description: "Output as NDJSON"}},
	"info domain":  {{Text: "--json", Description: "Output as NDJSON"}},
	"info forest":  {{Text: "--json", Description: "Output as NDJSON"}},
}

// ---------------------------------------------------------------------------
// Completer
// ---------------------------------------------------------------------------

func shellCompleter(in prompt.Document) []prompt.Suggest {
	text := in.TextBeforeCursor()
	args := strings.Fields(text)
	word := in.GetWordBeforeCursor()

	// First word: top-level commands.
	if len(args) == 0 || (len(args) == 1 && !strings.HasSuffix(text, " ")) {
		return prompt.FilterHasPrefix(topSuggestions, word, true)
	}

	cmd := args[0]
	switch cmd {
	case "attr":
		if len(args) == 1 || (len(args) == 2 && !strings.HasSuffix(text, " ")) {
			return prompt.FilterHasPrefix(attrSubSuggestions, word, true)
		}
		if len(args) >= 2 {
			if s, ok := flagSuggestions["attr "+args[1]]; ok {
				return prompt.FilterHasPrefix(s, word, true)
			}
		}
	case "create":
		if len(args) == 1 || (len(args) == 2 && !strings.HasSuffix(text, " ")) {
			return prompt.FilterHasPrefix(createSubSuggestions, word, true)
		}
		if len(args) >= 2 {
			if s, ok := flagSuggestions["create "+args[1]]; ok {
				return prompt.FilterHasPrefix(s, word, true)
			}
		}
	case "info":
		if len(args) == 1 || (len(args) == 2 && !strings.HasSuffix(text, " ")) {
			return prompt.FilterHasPrefix(infoSubSuggestions, word, true)
		}
		if len(args) >= 2 {
			if s, ok := flagSuggestions["info "+args[1]]; ok {
				return prompt.FilterHasPrefix(s, word, true)
			}
		}
	default:
		if s, ok := flagSuggestions[cmd]; ok {
			return prompt.FilterHasPrefix(s, word, true)
		}
	}
	return []prompt.Suggest{}
}

// ---------------------------------------------------------------------------
// Tokenizer — splits on whitespace, respects single and double quotes
// ---------------------------------------------------------------------------

func tokenize(s string) []string {
	var tokens []string
	var cur strings.Builder
	var quote rune
	inQuote := false

	for _, r := range s {
		switch {
		case inQuote:
			if r == quote {
				inQuote = false
			} else {
				cur.WriteRune(r)
			}
		case r == '\'' || r == '"':
			inQuote = true
			quote = r
		case unicode.IsSpace(r):
			if cur.Len() > 0 {
				tokens = append(tokens, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		tokens = append(tokens, cur.String())
	}
	return tokens
}

// ---------------------------------------------------------------------------
// Flag resetter — resets all local (non-persistent) flags to defaults before
// each command execution so results are deterministic across invocations.
// ---------------------------------------------------------------------------

func resetFlags(cmd *cobra.Command) {
	cmd.LocalNonPersistentFlags().VisitAll(func(f *pflag.Flag) {
		if f.Changed {
			_ = f.Value.Set(f.DefValue)
			f.Changed = false
		}
	})
	for _, sub := range cmd.Commands() {
		resetFlags(sub)
	}
}

// ---------------------------------------------------------------------------
// Shell executor
// ---------------------------------------------------------------------------

// shellMode guards against infinite recursion: if cobra can't find a matching
// subcommand it falls back to the root RunE, which must NOT restart the shell.
var shellMode bool

func buildExecutor(rootCmd *cobra.Command, common *commonOptions, client *adws.WSClient, restoreTerminal func()) func(string) {
	// Inject the persistent connection into cobra's context so every command
	// reuses the same session instead of re-dialling.
	ctx := context.WithValue(context.Background(), ctxClientKey{}, client)
	rootCmd.SetContext(ctx)

	return func(in string) {
		in = strings.TrimSpace(in)
		if in == "" {
			return
		}

		args := tokenize(in)
		if len(args) == 0 {
			return
		}

		switch args[0] {
		case "exit", "quit":
			fmt.Println("\nBye!")
			restoreTerminal()
			os.Exit(0)
		case "help", "?":
			_ = rootCmd.Usage()
			return
		}

		// Reset local flags so each invocation starts clean.
		resetFlags(rootCmd)

		rootCmd.SetArgs(args)
		if err := rootCmd.Execute(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		}

		// Restore the context after Execute (cobra may clear it internally).
		rootCmd.SetContext(ctx)
	}
}

// ---------------------------------------------------------------------------
// RunShell — entry point
// ---------------------------------------------------------------------------

func RunShell(rootCmd *cobra.Command, common *commonOptions) error {
	client, err := newClient(*common)
	if err != nil {
		return fmt.Errorf("connection setup failed: %w", err)
	}
	if err := client.Connect(); err != nil {
		return fmt.Errorf("connection failed: %w", err)
	}
	defer client.Close()

	fmt.Printf("sopa %s\n", version)
	fmt.Printf("Connected  %s  domain=%s  user=%s\n", common.dcAddr, common.domain, common.username)
	fmt.Printf("Type 'help' for commands or 'exit' to quit.\n\n")

	shellMode = true

	// In raw mode (maintained by go-prompt) bare \n does not imply \r, so
	// lines would staircase. Route all cobra output through crlfWriter.
	rootCmd.SetOut(crlfWriter{os.Stdout})
	rootCmd.SetErr(crlfWriter{os.Stderr})

	// Save terminal state before go-prompt enters raw mode so we can
	// restore it unconditionally on exit (go-prompt v0.2.6 does not
	// restore the ICRNL flag, leaving the terminal garbled after Ctrl-D
	// or the `exit` command).
	fd := int(os.Stdin.Fd())
	restoreTerminal := func() {}
	if oldState, terr := term.GetState(fd); terr == nil {
		restoreTerminal = func() { term.Restore(fd, oldState) }
	}
	defer restoreTerminal()

	prefix := fmt.Sprintf("[%s]> ", common.domain)

	p := prompt.New(
		buildExecutor(rootCmd, common, client, restoreTerminal),
		shellCompleter,
		prompt.OptionPrefix(prefix),
		prompt.OptionTitle("sopa ("+common.dcAddr+")"),
		prompt.OptionPrefixTextColor(prompt.Cyan),
		prompt.OptionPreviewSuggestionTextColor(prompt.Blue),
		prompt.OptionSelectedSuggestionBGColor(prompt.LightGray),
		prompt.OptionSuggestionBGColor(prompt.DarkGray),
	)
	p.Run()
	return nil
}
