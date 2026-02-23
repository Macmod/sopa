package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	adws "github.com/Macmod/sopa"
	"github.com/spf13/cobra"
)

var version = "v1.0.0"

type commonOptions struct {
	dcFQDN      string
	port        int
	ldapPort    int
	username    string
	password    string
	ntHash      string
	aesKey      string
	ccache      string
	pfxFile     string
	pfxPassword string
	certFile    string
	keyFile     string
	kerberos    bool
	domain      string
	baseDN      string
	debugXML    bool
	noColor     bool
}

func main() {
	rootCmd := newRootCmd()
	if err := rootCmd.Execute(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	var common commonOptions

	cmd := &cobra.Command{
		Use:           "sopa",
		Short:         "sopa - A practical client for ADWS operations",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.PersistentPreRun = func(_ *cobra.Command, _ []string) {
		// Ensure debug XML and other output respects --no-color.
		if common.noColor {
			_ = os.Setenv("NO_COLOR", "1")
		}
	}
	cmd.CompletionOptions.DisableDefaultCmd = true

	cmd.SetVersionTemplate("sopa {{.Version}}\n")

	pf := cmd.PersistentFlags()
	pf.StringVarP(&common.dcFQDN, "dc", "", "", "Domain Controller FQDN or IP (required)")
	pf.IntVarP(&common.port, "port", "P", 9389, "ADWS port")
	pf.IntVarP(&common.ldapPort, "ldap-port", "l", 389, "LDAP port used in SOAP headers (389=DC, 3268=GC)")
	pf.StringVarP(&common.username, "username", "u", "", "Username (required)")
	pf.StringVarP(&common.password, "password", "p", "", "Password (optional if --nthash, --ccache, --pfx, or --cert is provided)")
	pf.StringVarP(&common.ntHash, "nthash", "H", "", "NT hash for authentication (hex, optional)")
	pf.StringVar(&common.aesKey, "aes-key", "", "Kerberos AES-128 or AES-256 session key (hex, implies --kerberos, optional)")
	pf.StringVarP(&common.ccache, "ccache", "c", "", "Kerberos ccache path (optional)")
	pf.StringVar(&common.pfxFile, "pfx", "", "PKCS#12 (.pfx/.p12) certificate file for PKINIT authentication (optional)")
	pf.StringVar(&common.pfxPassword, "pfx-password", "", "Password for the PFX file (optional, default empty)")
	pf.StringVar(&common.certFile, "cert", "", "PEM certificate file for PKINIT authentication (use with --key)")
	pf.StringVar(&common.keyFile, "key", "", "PEM RSA private key file for PKINIT authentication (use with --cert)")
	pf.BoolVarP(&common.kerberos, "kerberos", "k", false, "Force Kerberos authentication")
	pf.StringVarP(&common.domain, "domain", "d", "", "Domain name (required)")
	pf.StringVarP(&common.baseDN, "basedn", "b", "", "Base DN (default: derived from --domain)")
	pf.BoolVarP(&common.debugXML, "debug-xml", "x", false, "Print raw SOAP XML requests and responses")
	pf.BoolVarP(&common.noColor, "no-color", "N", false, "Disable colored output")

	cmd.AddCommand(newQueryCmd(&common))
	cmd.AddCommand(newGetCmd(&common))
	cmd.AddCommand(newAttrCmd(&common))
	cmd.AddCommand(newCreateCmd(&common))
	cmd.AddCommand(newDeleteCmd(&common))
	cmd.AddCommand(newSetPasswordCmd(&common))
	cmd.AddCommand(newChangePasswordCmd(&common))
	cmd.AddCommand(newTranslateNameCmd(&common))
	cmd.AddCommand(newGroupsCmd(&common))
	cmd.AddCommand(newGroupMembersCmd(&common))
	cmd.AddCommand(newOptFeatureCmd(&common))
	cmd.AddCommand(newInfoCmd(&common))
	cmd.AddCommand(newMexCmd(&common))

	cmd.AddCommand(&cobra.Command{
		Use:     "version",
		Short:   "Print version",
		Aliases: []string{"v"},
		Run: func(_ *cobra.Command, _ []string) {
			fmt.Printf("sopa %s\n", version)
		},
	})

	cmd.SetHelpCommand(&cobra.Command{Hidden: true})
	cmd.SetUsageTemplate(cmd.UsageTemplate())

	return cmd
}

func normalizeCommonOptions(common *commonOptions) error {
	if common == nil {
		return fmt.Errorf("common options are required")
	}
	common.dcFQDN = strings.TrimSpace(common.dcFQDN)
	common.username = strings.TrimSpace(common.username)
	common.domain = strings.TrimSpace(common.domain)
	common.ntHash = strings.TrimSpace(common.ntHash)
	common.aesKey = strings.TrimSpace(common.aesKey)
	common.ccache = strings.TrimSpace(common.ccache)
	common.pfxFile = strings.TrimSpace(common.pfxFile)
	common.certFile = strings.TrimSpace(common.certFile)
	common.keyFile = strings.TrimSpace(common.keyFile)
	common.baseDN = strings.TrimSpace(common.baseDN)

	hasCert := common.pfxFile != "" || common.certFile != ""
	if common.dcFQDN == "" || common.username == "" || common.domain == "" {
		return fmt.Errorf("--dc, --username, and --domain are required")
	}
	if strings.TrimSpace(common.password) == "" && common.ntHash == "" && common.aesKey == "" && common.ccache == "" && !hasCert {
		return fmt.Errorf("provide one of --password, --nthash, --aes-key, --ccache, --pfx, or --cert/--key")
	}
	if common.certFile != "" && common.keyFile == "" {
		return fmt.Errorf("--key is required when --cert is set")
	}
	if common.baseDN == "" {
		common.baseDN = domainToDN(common.domain)
	}
	return nil
}

func newClient(common commonOptions) (*adws.WSClient, error) {
	client, err := adws.NewWSClient(adws.Config{
		DCFQDN:      strings.TrimSpace(common.dcFQDN),
		Port:        common.port,
		LDAPPort:    common.ldapPort,
		Username:    strings.TrimSpace(common.username),
		Password:    common.password,
		NTHash:      strings.TrimSpace(common.ntHash),
		AESKey:      strings.TrimSpace(common.aesKey),
		CCachePath:  strings.TrimSpace(common.ccache),
		PFXFile:     common.pfxFile,
		PFXPassword: common.pfxPassword,
		CertFile:    common.certFile,
		KeyFile:     common.keyFile,
		UseKerberos: common.kerberos,
		Domain:      strings.TrimSpace(common.domain),
		DebugXML:    common.debugXML,
	})
	if err != nil {
		return nil, err
	}
	return client, nil
}

type ctxClientKey struct{}

func clientFromContext(ctx context.Context) (*adws.WSClient, bool) {
	if ctx == nil {
		return nil, false
	}
	v := ctx.Value(ctxClientKey{})
	if v == nil {
		return nil, false
	}
	c, ok := v.(*adws.WSClient)
	return c, ok && c != nil
}

func withClient(cmd *cobra.Command, common commonOptions, fn func(*adws.WSClient) error) error {
	if cmd != nil {
		if existing, ok := clientFromContext(cmd.Context()); ok {
			return fn(existing)
		}
	}

	client, err := newClient(common)
	if err != nil {
		return err
	}
	defer client.Close()
	if err := client.Connect(); err != nil {
		return err
	}
	return fn(client)
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	return out
}

// splitCSVValues splits a comma-separated list but preserves leading/trailing spaces.
// This is important for attribute values where whitespace can be meaningful.
func splitCSVValues(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	return out
}

func combineErrors(errs ...error) error {
	var out error
	for _, err := range errs {
		if err == nil {
			continue
		}
		out = errors.Join(out, err)
	}
	return out
}
