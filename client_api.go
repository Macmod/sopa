// Package adws - High-level ADWS client for Active Directory query and transfer operations
package adws

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	soap "github.com/Macmod/go-adws/soap"
	"github.com/Macmod/go-adws/transport"
	"github.com/Macmod/go-adws/wscap"
	"github.com/Macmod/go-adws/wsenum"
	"github.com/Macmod/go-adws/wsmex"
	"github.com/Macmod/go-adws/wstransfer"
	"github.com/mattn/go-isatty"
)

const (
	defaultADWSPort           = 9389
	defaultLDAPPort           = 389
	defaultConnectTimeout     = 30 * time.Second
	defaultMaxElementsPerPull = 10
)

// ADWSItem is the public alias for an ADWS object item.
type ADWSItem = soap.ADWSItem

// ADWSValue is the public alias for an ADWS attribute value.
type ADWSValue = soap.ADWSValue

// WSClient represents an ADWS client for querying and transfer operations in Active Directory.
//
// ADWS provides an alternative to traditional LDAP (ports 389/3268) by using
// port 9389 with SOAP/XML over an authenticated and encrypted channel.
//
// Protocol stack (bottom to top):
//   1. TCP connection to dc.domain.com:9389
//   2. NNS (.NET NegotiateStream) - NTLM/Kerberos authentication with signing/sealing
//   3. NMF (.NET Message Framing) - Record boundaries and encoding negotiation
//   4. SOAP/XML - WS-Enumeration/WS-Transfer protocol operations
type WSClient struct {
	dcFQDN      string        // DC fully-qualified domain name
	port        int           // ADWS port (default 9389)
	ldapPort    int           // LDAP instance port advertised in SOAP headers (default 389)
	username    string        // Domain\username or username@domain
	password    string        // Password
	ntHash      string        // NT hash (hex)
	aesKey      string        // Kerberos AES key (hex, 32 or 64 chars)
	ccache      string        // Kerberos ccache path
	pfxFile     string        // PKCS#12 certificate file for PKINIT
	pfxPassword string        // Password for PFX file
	certFile    string        // PEM certificate file for PKINIT
	keyFile     string        // PEM private key file for PKINIT
	kerberos    bool          // Prefer Kerberos/SPNEGO when true
	domain      string        // Domain name
	timeout     time.Duration // Connection timeout
	tlsConfig   *tls.Config   // TLS config (for future TLS support)

	// Connection state
	conn      net.Conn                 // TCP connection
	nnsConn   *transport.NNSConnection // NNS layer
	nmfConn   *transport.NMFConnection // NMF layer
	connected bool                     // Connection state
	debugXML  bool                     // Print raw SOAP XML for debugging
}

// Config contains ADWS client configuration.
type Config struct {
	DCFQDN      string        // DC fully-qualified domain name (required)
	Port        int           // ADWS port (default 9389)
	LDAPPort    int           // LDAP port used in SOAP headers for the target directory service (default 389; use 3268 for GC)
	Username    string        // Domain\username or username@domain (required)
	Password    string        // Password (optional if NTHash/CCachePath/PFX/Cert provided)
	NTHash      string        // NT hash auth (optional)
	AESKey      string        // Kerberos AES-128 or AES-256 session key, hex-encoded (optional, implies Kerberos)
	CCachePath  string        // Kerberos ccache path (optional, implies Kerberos)
	PFXFile     string        // PKCS#12 (.pfx/.p12) certificate file for PKINIT (optional)
	PFXPassword string        // Password for PFX file (optional, default empty)
	CertFile    string        // PEM certificate file for PKINIT (use with KeyFile)
	KeyFile     string        // PEM RSA private key file for PKINIT (use with CertFile)
	UseKerberos bool          // Use SPNEGO/Kerberos negotiation
	Domain      string        // Domain name (required)
	Timeout     time.Duration // Connection timeout (default 30s)
	UseTLS      bool          // Use TLS (future - currently not supported by ADWS)
	DebugXML    bool          // Print raw SOAP XML when true (or via ADWS_DEBUG_XML=1)
}

// NewWSClient creates a new ADWS client with the given configuration.
// Credential fields (Username, Password, etc.) are validated at Connect() time,
// so callers that only intend to call GetMetadata() may omit them.
func NewWSClient(cfg Config) (*WSClient, error) {
	if cfg.DCFQDN == "" {
		return nil, fmt.Errorf("DCFQDN is required")
	}
	if cfg.CertFile != "" && cfg.KeyFile == "" {
		return nil, fmt.Errorf("KeyFile is required when CertFile is set")
	}

	if cfg.Port == 0 {
		cfg.Port = defaultADWSPort
	}
	if cfg.LDAPPort == 0 {
		cfg.LDAPPort = defaultLDAPPort
	}
	if cfg.LDAPPort <= 0 || cfg.LDAPPort > 65535 {
		return nil, fmt.Errorf("LDAPPort out of range: %d", cfg.LDAPPort)
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = defaultConnectTimeout
	}

	hasCert := cfg.PFXFile != "" || cfg.CertFile != ""
	return &WSClient{
		dcFQDN:      cfg.DCFQDN,
		port:        cfg.Port,
		ldapPort:    cfg.LDAPPort,
		username:    cfg.Username,
		password:    cfg.Password,
		ntHash:      cfg.NTHash,
		aesKey:      cfg.AESKey,
		ccache:      cfg.CCachePath,
		pfxFile:     cfg.PFXFile,
		pfxPassword: cfg.PFXPassword,
		certFile:    cfg.CertFile,
		keyFile:     cfg.KeyFile,
		kerberos:    cfg.UseKerberos || cfg.CCachePath != "" || cfg.AESKey != "" || hasCert,
		domain:      cfg.Domain,
		timeout:     cfg.Timeout,
		debugXML:    cfg.DebugXML,
	}, nil
}

// Connect establishes a connection to the ADWS server.
func (c *WSClient) Connect() error {
	if c.connected {
		return fmt.Errorf("already connected")
	}

	// Validate credentials here — they are only needed for authenticated connections.
	if c.username == "" {
		return fmt.Errorf("Username is required")
	}
	if c.domain == "" {
		return fmt.Errorf("Domain is required")
	}
	hasCert := c.pfxFile != "" || c.certFile != ""
	if c.password == "" && c.ntHash == "" && c.aesKey == "" && c.ccache == "" && !hasCert {
		return fmt.Errorf("one of Password, NTHash, AESKey, CCachePath, PFXFile, or CertFile+KeyFile is required")
	}

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", c.dcFQDN, c.port), c.timeout)
	if err != nil {
		return fmt.Errorf("failed to connect to %s:%d: %w", c.dcFQDN, c.port, err)
	}
	c.conn = conn

	targetSPN := c.buildTargetSPN(c.dcFQDN)
	c.nnsConn = c.newNNSConnection(c.conn, targetSPN)

	c.nmfConn = transport.NewNMFConnection(c.nnsConn, c.dcFQDN, c.port)

	resource := wsenum.EndpointEnumeration
	if err := c.nmfConn.Connect(resource); err != nil {
		c.conn.Close()
		return fmt.Errorf("NMF connection failed: %w", err)
	}

	c.connected = true
	return nil
}

// Query performs an LDAP query via ADWS and returns all results.
func (c *WSClient) Query(baseDN, filter string, attrs []string, scope int) ([]ADWSItem, error) {
	if !c.connected {
		return nil, fmt.Errorf("not connected")
	}

	baseDN, filter, attrs, err := wsenum.ValidateQueryInput(baseDN, filter, attrs, scope)
	if err != nil {
		return nil, err
	}

	service := wsenum.NewWSEnumClient(c.nmfConn, c.dcFQDN, c.port, c.ldapPort, c.debugPrintXML, c.debugPrintPullResult)
	return wsenum.ExecuteQuery(service, baseDN, filter, attrs, scope, defaultMaxElementsPerPull, defaultMaxElementsPerPull, nil)
}

// Get retrieves a single AD object by distinguished name.
func (c *WSClient) Get(dn string, attrs []string) (*ADWSItem, error) {
	if !c.connected {
		return nil, fmt.Errorf("not connected")
	}

	dn = strings.TrimSpace(dn)
	if dn == "" {
		return nil, fmt.Errorf("dn is required")
	}

	return c.WSTransferGet(dn, attrs)
}

// GetMetadata fetches and parses the WS-MetadataExchange document from the unauthenticated
// ADWS MEX endpoint. No credentials are required.
func (c *WSClient) GetMetadata() (*wsmex.ADWSMetadata, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", c.dcFQDN, c.port), c.timeout)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s:%d: %w", c.dcFQDN, c.port, err)
	}

	targetSPN := c.buildTargetSPN(c.dcFQDN)
	nnsConn := transport.NewNNSConnectionAnonymous(conn, targetSPN, false, transport.ProtectionNone)

	nmfConn := transport.NewNMFConnection(nnsConn, c.dcFQDN, c.port)
	if err := nmfConn.Connect(wsmex.EndpointMEX); err != nil {
		_ = nnsConn.Close()
		return nil, fmt.Errorf("NMF connection to MEX endpoint failed: %w", err)
	}
	defer nnsConn.Close()

	client := wsmex.NewWSMexClient(nmfConn, c.dcFQDN, c.port, c.debugPrintXML)
	return client.GetMetadata()
}

// Close closes the ADWS connection.
func (c *WSClient) Close() error {
	if !c.connected {
		return nil
	}

	var closeErr error
	if c.nnsConn != nil {
		closeErr = errors.Join(closeErr, c.nnsConn.Close())
	} else if c.conn != nil {
		closeErr = errors.Join(closeErr, c.conn.Close())
	}

	c.connected = false
	return closeErr
}

// QueryWithCallback performs an LDAP query and calls a callback for each batch of results.
func (c *WSClient) QueryWithCallback(baseDN, filter string, attrs []string, scope int, callback func(items []ADWSItem) error) error {
	if !c.connected {
		return fmt.Errorf("not connected")
	}
	if callback == nil {
		return fmt.Errorf("callback is required")
	}

	baseDN, filter, attrs, err := wsenum.ValidateQueryInput(baseDN, filter, attrs, scope)
	if err != nil {
		return err
	}

	batchCh := make(chan []ADWSItem, 1)
	execErrCh := make(chan error, 1)

	go func() {
		execErrCh <- c.QueryWithBatchChannel(baseDN, filter, attrs, scope, defaultMaxElementsPerPull, batchCh)
		close(batchCh)
	}()

	var callbackErr error
	for batch := range batchCh {
		if callbackErr != nil {
			continue
		}
		if err := callback(batch); err != nil {
			callbackErr = fmt.Errorf("callback error: %w", err)
		}
	}

	execErr := <-execErrCh
	if execErr != nil {
		return execErr
	}

	return callbackErr
}

// QueryWithBatchChannel performs an LDAP query and streams each Pull batch to batchChannel.
func (c *WSClient) QueryWithBatchChannel(baseDN, filter string, attrs []string, scope, maxElementsPerPull int, batchChannel chan<- []ADWSItem) error {
	if !c.connected {
		return fmt.Errorf("not connected")
	}
	if batchChannel == nil {
		return fmt.Errorf("batchChannel is required")
	}

	baseDN, filter, attrs, err := wsenum.ValidateQueryInput(baseDN, filter, attrs, scope)
	if err != nil {
		return err
	}

	service := wsenum.NewWSEnumClient(c.nmfConn, c.dcFQDN, c.port, c.ldapPort, c.debugPrintXML, c.debugPrintPullResult)
	_, err = wsenum.ExecuteQuery(service, baseDN, filter, attrs, scope, maxElementsPerPull, defaultMaxElementsPerPull, batchChannel)
	return err
}

func (c *WSClient) isDebugXML() bool {
	if c.debugXML {
		return true
	}
	return os.Getenv("ADWS_DEBUG_XML") == "1"
}

func (c *WSClient) debugPrintXML(label, xmlPayload string) {
	if !c.isDebugXML() {
		return
	}
	pretty := soap.PrettyXML(xmlPayload)
	if c.shouldColorDebugXML() {
		pretty = colorizeXMLTags(pretty)
	}
	fmt.Printf("[adws-debug] %s XML:\n%s\n", label, pretty)
}

func (c *WSClient) shouldColorDebugXML() bool {
	if strings.TrimSpace(os.Getenv("NO_COLOR")) != "" {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(os.Getenv("TERM")), "dumb") {
		return false
	}
	if strings.TrimSpace(os.Getenv("SOPA_FORCE_COLOR")) == "1" {
		return true
	}
	return isatty.IsTerminal(os.Stdout.Fd()) || isatty.IsCygwinTerminal(os.Stdout.Fd())
}

func colorizeXMLTags(prettyXML string) string {
	// Minimal highlighting: colorize "<...>" segments.
	const (
		cCyan  = "\x1b[36m"
		cReset = "\x1b[0m"
	)

	var b strings.Builder
	b.Grow(len(prettyXML) + 32)
	for i := 0; i < len(prettyXML); i++ {
		ch := prettyXML[i]
		if ch != '<' {
			b.WriteByte(ch)
			continue
		}

		j := strings.IndexByte(prettyXML[i:], '>')
		if j < 0 {
			b.WriteByte(ch)
			continue
		}
		j = i + j

		b.WriteString(cCyan)
		b.WriteString(prettyXML[i : j+1])
		b.WriteString(cReset)
		i = j
	}
	return b.String()
}

func (c *WSClient) debugPrintPullResult(pr *soap.PullResponse) {
	if !c.isDebugXML() {
		return
	}
	fmt.Printf("[adws-debug] Parsed pull items=%d end=%v nextCtx=%q\n", len(pr.Items), pr.EndOfSequence, pr.EnumerationContext)
}

// IsConnected returns true if the client is connected.
func (c *WSClient) IsConnected() bool {
	return c.connected
}

// GetDCFQDN returns the DC FQDN this client is connected to.
func (c *WSClient) GetDCFQDN() string {
	return c.dcFQDN
}

// SetTimeout sets the connection timeout.
func (c *WSClient) SetTimeout(timeout time.Duration) {
	c.timeout = timeout
}

// SetDebugXML enables/disables raw SOAP response logging.
func (c *WSClient) SetDebugXML(enabled bool) {
	c.debugXML = enabled
}

// WSTransferGet executes a WS-Transfer Get against the Resource endpoint.
func (c *WSClient) WSTransferGet(dn string, attrs []string) (*ADWSItem, error) {
	if !c.connected {
		return nil, fmt.Errorf("not connected")
	}

	result, err := c.withEndpointWSTransferClientResult(wstransfer.EndpointResource, func(tx *wstransfer.WSTransferClient) (interface{}, error) {
		return tx.Get(dn, attrs)
	})
	if err != nil {
		return nil, err
	}
	if item, ok := result.(*ADWSItem); ok {
		return item, nil
	}
	return nil, nil
}

// WSTransferDelete executes a WS-Transfer Delete against the Resource endpoint.
func (c *WSClient) WSTransferDelete(dn string) error {
	if !c.connected {
		return fmt.Errorf("not connected")
	}

	_, err := c.withEndpointWSTransferClientResult(wstransfer.EndpointResource, func(tx *wstransfer.WSTransferClient) (interface{}, error) {
		return nil, tx.Delete(dn)
	})
	return err
}

// WSTransferPut executes a WS-Transfer Put against the Resource endpoint.
func (c *WSClient) WSTransferPut(dn, instanceXML string) error {
	if !c.connected {
		return fmt.Errorf("not connected")
	}

	_, err := c.withEndpointWSTransferClientResult(wstransfer.EndpointResource, func(tx *wstransfer.WSTransferClient) (interface{}, error) {
		return nil, tx.Put(dn, instanceXML)
	})
	return err
}

// WSTransferModifyAttribute performs a WS-Transfer Put using an IMDA ModifyRequest.
//
// operation must be one of: add, replace, delete.
// attr may be either a local attribute name (e.g. "description") or a fully-qualified type (e.g. "addata:description").
// Values are treated as xsd:string.
func (c *WSClient) WSTransferModifyAttribute(dn, operation, attr string, values []string) error {
	if !c.connected {
		return fmt.Errorf("not connected")
	}
	modifyXML, err := soap.BuildModifyRequest(operation, attr, values, "xsd:string")
	if err != nil {
		return err
	}
	return c.WSTransferPut(dn, modifyXML)
}

// WSTransferCreate executes a WS-Transfer Create against the ResourceFactory endpoint.
//
// The returned address is best-effort and may be empty if the server response does not include
// a parsable ResourceCreated/Address or objectReferenceProperty.
func (c *WSClient) WSTransferCreate(instanceXML string) (string, error) {
	if !c.connected {
		return "", fmt.Errorf("not connected")
	}

	return c.withEndpointWSTransferClient(wstransfer.EndpointResourceFactory, func(tx *wstransfer.WSTransferClient) (string, error) {
		return tx.Create(instanceXML)
	})
}

// WSTransferCreateComputer executes a WS-Transfer Create (IMDA AddRequest) against the
// ResourceFactory endpoint to create a simple computer object under parentDN.
//
// This is a state-changing operation.
func (c *WSClient) WSTransferCreateComputer(parentDN, computerName string) (string, error) {
	if !c.connected {
		return "", fmt.Errorf("not connected")
	}

	return c.withEndpointWSTransferClient(wstransfer.EndpointResourceFactory, func(tx *wstransfer.WSTransferClient) (string, error) {
		return tx.CreateComputer(parentDN, computerName)
	})
}

// WSTransferAddComputer executes a WS-Transfer Create (IMDA AddRequest) against the
// ResourceFactory endpoint to create a computer account under parentDN.
//
// This mirrors SharpADWS' AddComputer method and sets unicodePwd, dNSHostName,
// userAccountControl, and servicePrincipalName.
func (c *WSClient) WSTransferAddComputer(parentDN, computerName, computerPass string) (string, error) {
	if !c.connected {
		return "", fmt.Errorf("not connected")
	}

	return c.withEndpointWSTransferClient(wstransfer.EndpointResourceFactory, func(tx *wstransfer.WSTransferClient) (string, error) {
		return tx.AddComputer(parentDN, computerName, c.domain, computerPass)
	})
}

// WSTransferAddUser creates a user object under parentDN via ResourceFactory.
func (c *WSClient) WSTransferAddUser(parentDN, userName, userPass string, enabled bool) (string, error) {
	if !c.connected {
		return "", fmt.Errorf("not connected")
	}

	return c.withEndpointWSTransferClient(wstransfer.EndpointResourceFactory, func(tx *wstransfer.WSTransferClient) (string, error) {
		return tx.AddUser(parentDN, userName, c.domain, userPass, enabled)
	})
}

// WSTransferAddGroup creates a group object under parentDN via ResourceFactory.
func (c *WSClient) WSTransferAddGroup(parentDN, groupName, groupType string) (string, error) {
	if !c.connected {
		return "", fmt.Errorf("not connected")
	}

	return c.withEndpointWSTransferClient(wstransfer.EndpointResourceFactory, func(tx *wstransfer.WSTransferClient) (string, error) {
		return tx.AddGroup(parentDN, groupName, groupType)
	})
}

// WSTransferAddOU creates an organizationalUnit object under parentDN via ResourceFactory.
func (c *WSClient) WSTransferAddOU(parentDN, ouName string) (string, error) {
	if !c.connected {
		return "", fmt.Errorf("not connected")
	}

	return c.withEndpointWSTransferClient(wstransfer.EndpointResourceFactory, func(tx *wstransfer.WSTransferClient) (string, error) {
		return tx.AddOU(parentDN, ouName)
	})
}

// WSTransferAddContainer creates a container object under parentDN via ResourceFactory.
func (c *WSClient) WSTransferAddContainer(parentDN, cn string) (string, error) {
	if !c.connected {
		return "", fmt.Errorf("not connected")
	}

	return c.withEndpointWSTransferClient(wstransfer.EndpointResourceFactory, func(tx *wstransfer.WSTransferClient) (string, error) {
		return tx.AddContainer(parentDN, cn)
	})
}

func (c *WSClient) withEndpointWSTransferClient(endpoint string, fn func(tx *wstransfer.WSTransferClient) (string, error)) (string, error) {
	result, err := c.withEndpointWSTransferClientResult(endpoint, func(tx *wstransfer.WSTransferClient) (interface{}, error) {
		return fn(tx)
	})
	if err != nil {
		return "", err
	}
	if str, ok := result.(string); ok {
		return str, nil
	}
	return "", nil
}

func (c *WSClient) withEndpointWSTransferClientResult(endpoint string, fn func(tx *wstransfer.WSTransferClient) (interface{}, error)) (interface{}, error) {
	if fn == nil {
		return nil, fmt.Errorf("fn is required")
	}

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", c.dcFQDN, c.port), c.timeout)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s:%d: %w", c.dcFQDN, c.port, err)
	}

	targetSPN := c.buildTargetSPN(c.dcFQDN)
	nnsConn := c.newNNSConnection(conn, targetSPN)

	nmfConn := transport.NewNMFConnection(nnsConn, c.dcFQDN, c.port)
	if err := nmfConn.Connect(endpoint); err != nil {
		_ = nnsConn.Close()
		return nil, fmt.Errorf("NMF connection failed for endpoint %s: %w", endpoint, err)
	}
	defer nnsConn.Close()

	tx := wstransfer.NewWSTransferClient(nmfConn, c.dcFQDN, c.port, endpoint, c.ldapPort, c.debugPrintXML)
	return fn(tx)
}

func (c *WSClient) buildTargetSPN(target string) string {
	host := target

	if c.kerberos {
		if ip := net.ParseIP(target); ip != nil {
			if names, err := net.LookupAddr(target); err == nil && len(names) > 0 {
				host = strings.TrimSuffix(strings.TrimSpace(names[0]), ".")
			}
		}
	}

	return fmt.Sprintf("host/%s", host)
}

func (c *WSClient) newNNSConnection(conn net.Conn, targetSPN string) *transport.NNSConnection {
	chosenLevel := transport.ProtectionEncryptAndSign

	// PKINIT: PFX takes precedence over cert+key.
	if c.pfxFile != "" || c.certFile != "" {
		var (
			rsaKey   *rsa.PrivateKey
			x509Cert *x509.Certificate
			loadErr  error
		)
		if c.pfxFile != "" {
			rsaKey, x509Cert, loadErr = transport.LoadPFX(c.pfxFile, c.pfxPassword)
		} else {
			rsaKey, x509Cert, loadErr = transport.LoadPEM(c.certFile, c.keyFile)
		}
		if loadErr == nil {
			return transport.NewNNSConnectionWithPKINIT(conn, c.domain, c.username, x509Cert, rsaKey, targetSPN, chosenLevel)
		}
		// If credential load fails, fall through so Connect() surfaces the real error at auth time.
		_, _ = fmt.Fprintf(os.Stderr, "sopa: PKINIT credential load error: %v\n", loadErr)
	}

	if c.ccache != "" {
		return transport.NewNNSConnectionWithCCache(
			conn,
			c.domain,
			c.username,
			c.ccache,
			targetSPN,
			chosenLevel,
		)
	}

	if c.aesKey != "" {
		return transport.NewNNSConnectionWithAESKey(
			conn,
			c.domain,
			c.username,
			c.aesKey,
			targetSPN,
			chosenLevel,
		)
	}

	if c.ntHash != "" {
		return transport.NewNNSConnectionWithNTHash(
			conn,
			c.domain,
			c.username,
			c.ntHash,
			targetSPN,
			c.kerberos,
			chosenLevel,
		)
	}

	return transport.NewNNSConnection(
		conn,
		c.domain,
		c.username,
		c.password,
		targetSPN,
		c.kerberos,
		chosenLevel,
	)
}

// NameTranslateResult is the public alias for an MS-ADCAP TranslateName result.
type NameTranslateResult = soap.NameTranslateResult

// ADCAPActiveDirectoryObject is the public alias for an MS-ADCAP ActiveDirectoryObject.
type ADCAPActiveDirectoryObject = soap.ADCAPActiveDirectoryObject

// ADCAPActiveDirectoryPrincipal is the public alias for an MS-ADCAP ActiveDirectoryPrincipal.
type ADCAPActiveDirectoryPrincipal = soap.ADCAPActiveDirectoryPrincipal

// ADCAPActiveDirectoryGroup is the public alias for an MS-ADCAP ActiveDirectoryGroup.
type ADCAPActiveDirectoryGroup = soap.ADCAPActiveDirectoryGroup

// ADCAPActiveDirectoryDomain is the public alias for an MS-ADCAP ActiveDirectoryDomain.
type ADCAPActiveDirectoryDomain = soap.ADCAPActiveDirectoryDomain

// ADCAPActiveDirectoryForest is the public alias for an MS-ADCAP ActiveDirectoryForest.
type ADCAPActiveDirectoryForest = soap.ADCAPActiveDirectoryForest

// ADCAPActiveDirectoryDomainController is the public alias for an MS-ADCAP ActiveDirectoryDomainController.
type ADCAPActiveDirectoryDomainController = soap.ADCAPActiveDirectoryDomainController

// ADCAPVersionInfo is the public alias for an MS-ADCAP GetVersion result.
type ADCAPVersionInfo = soap.ADCAPVersionInfo

// ADCAPSetPassword sets the password for the specified account DN in the specified partition.
func (c *WSClient) ADCAPSetPassword(accountDN, partitionDN, newPassword string) error {
	if !c.connected {
		return fmt.Errorf("not connected")
	}
	accountDN = strings.TrimSpace(accountDN)
	partitionDN = strings.TrimSpace(partitionDN)
	if accountDN == "" {
		return fmt.Errorf("accountDN is required")
	}
	if partitionDN == "" {
		return fmt.Errorf("partitionDN is required")
	}

	return c.withAccountManagementClient(func(am *wscap.WSCapClient) error {
		return am.SetPassword(accountDN, partitionDN, newPassword)
	})
}

// ADCAPChangePassword changes the password for the specified account DN in the specified partition.
func (c *WSClient) ADCAPChangePassword(accountDN, partitionDN, oldPassword, newPassword string) error {
	if !c.connected {
		return fmt.Errorf("not connected")
	}
	accountDN = strings.TrimSpace(accountDN)
	partitionDN = strings.TrimSpace(partitionDN)
	if accountDN == "" {
		return fmt.Errorf("accountDN is required")
	}
	if partitionDN == "" {
		return fmt.Errorf("partitionDN is required")
	}

	return c.withAccountManagementClient(func(am *wscap.WSCapClient) error {
		return am.ChangePassword(accountDN, partitionDN, oldPassword, newPassword)
	})
}

// ADCAPTranslateName translates an array of names from one format to another.
// Valid formats: DistinguishedName, CanonicalName.
func (c *WSClient) ADCAPTranslateName(formatOffered, formatDesired string, names []string) ([]NameTranslateResult, error) {
	if !c.connected {
		return nil, fmt.Errorf("not connected")
	}
	return c.withAccountManagementClientResults(func(am *wscap.WSCapClient) ([]NameTranslateResult, error) {
		return am.TranslateName(formatOffered, formatDesired, names)
	})
}

// ADCAPGetADGroupMember returns the members of the specified group.
func (c *WSClient) ADCAPGetADGroupMember(groupDN, partitionDN string, recursive bool) ([]ADCAPActiveDirectoryPrincipal, error) {
	if !c.connected {
		return nil, fmt.Errorf("not connected")
	}
	groupDN = strings.TrimSpace(groupDN)
	partitionDN = strings.TrimSpace(partitionDN)
	if groupDN == "" {
		return nil, fmt.Errorf("groupDN is required")
	}
	if partitionDN == "" {
		return nil, fmt.Errorf("partitionDN is required")
	}

	var out []ADCAPActiveDirectoryPrincipal
	err := c.withAccountManagementClient(func(am *wscap.WSCapClient) error {
		res, err := am.GetADGroupMember(groupDN, partitionDN, recursive)
		if err != nil {
			return err
		}
		out = res
		return nil
	})
	return out, err
}

// ADCAPGetADPrincipalAuthorizationGroup returns the security-enabled groups used for authorization for a principal.
func (c *WSClient) ADCAPGetADPrincipalAuthorizationGroup(principalDN, partitionDN string) ([]ADCAPActiveDirectoryGroup, error) {
	if !c.connected {
		return nil, fmt.Errorf("not connected")
	}
	principalDN = strings.TrimSpace(principalDN)
	partitionDN = strings.TrimSpace(partitionDN)
	if principalDN == "" {
		return nil, fmt.Errorf("principalDN is required")
	}
	if partitionDN == "" {
		return nil, fmt.Errorf("partitionDN is required")
	}

	var out []ADCAPActiveDirectoryGroup
	err := c.withAccountManagementClient(func(am *wscap.WSCapClient) error {
		res, err := am.GetADPrincipalAuthorizationGroup(partitionDN, principalDN)
		if err != nil {
			return err
		}
		out = res
		return nil
	})
	return out, err
}

// ADCAPGetADPrincipalGroupMembership returns a set of groups associated with the specified principal.
//
// Note: per MS-ADCAP, this returns direct group membership only (no transitive expansion).
func (c *WSClient) ADCAPGetADPrincipalGroupMembership(principalDN, partitionDN, resourceContextPartition, resourceContextServer string) ([]ADCAPActiveDirectoryGroup, error) {
	if !c.connected {
		return nil, fmt.Errorf("not connected")
	}
	principalDN = strings.TrimSpace(principalDN)
	partitionDN = strings.TrimSpace(partitionDN)
	if principalDN == "" {
		return nil, fmt.Errorf("principalDN is required")
	}
	if partitionDN == "" {
		return nil, fmt.Errorf("partitionDN is required")
	}

	var out []ADCAPActiveDirectoryGroup
	err := c.withAccountManagementClient(func(am *wscap.WSCapClient) error {
		res, err := am.GetADPrincipalGroupMembership(partitionDN, principalDN, resourceContextPartition, resourceContextServer)
		if err != nil {
			return err
		}
		out = res
		return nil
	})
	return out, err
}

// PrincipalGroupMembership returns a set of groups associated with the specified principal,
// using the MS-ADCAP GetADPrincipalGroupMembership custom action.
//
// Note: per MS-ADCAP, no transitive group membership evaluation is performed.
func (c *WSClient) PrincipalGroupMembership(principalDN string) ([]ADWSItem, error) {
	if !c.connected {
		return nil, fmt.Errorf("not connected")
	}
	principalDN = strings.TrimSpace(principalDN)
	if principalDN == "" {
		return nil, fmt.Errorf("principalDN is required")
	}
	partitionDN := c.domainToBaseDN()

	groups, err := c.ADCAPGetADPrincipalGroupMembership(principalDN, partitionDN, "", "")
	if err != nil {
		return nil, err
	}

	out := make([]ADWSItem, 0, len(groups))
	for _, g := range groups {
		dn := strings.TrimSpace(g.DistinguishedName)
		if dn == "" {
			dn = strings.TrimSpace(g.Name)
		}
		if dn == "" {
			dn = strings.TrimSpace(g.SamAccountName)
		}
		out = append(out, ADWSItem{ObjectGUID: g.ObjectGuid, DistinguishedName: dn, Attributes: map[string][]ADWSValue{}})
	}
	return out, nil
}

// PrincipalAuthorizationGroups returns the security-enabled groups used for authorization decisions
// for the specified principal, using the MS-ADCAP GetADPrincipalAuthorizationGroup custom action.
func (c *WSClient) PrincipalAuthorizationGroups(principalDN string) ([]ADWSItem, error) {
	if !c.connected {
		return nil, fmt.Errorf("not connected")
	}
	principalDN = strings.TrimSpace(principalDN)
	if principalDN == "" {
		return nil, fmt.Errorf("principalDN is required")
	}
	partitionDN := c.domainToBaseDN()

	groups, err := c.ADCAPGetADPrincipalAuthorizationGroup(principalDN, partitionDN)
	if err != nil {
		return nil, err
	}

	out := make([]ADWSItem, 0, len(groups))
	for _, g := range groups {
		dn := strings.TrimSpace(g.DistinguishedName)
		if dn == "" {
			dn = strings.TrimSpace(g.Name)
		}
		if dn == "" {
			dn = strings.TrimSpace(g.SamAccountName)
		}
		out = append(out, ADWSItem{ObjectGUID: g.ObjectGuid, DistinguishedName: dn, Attributes: map[string][]ADWSValue{}})
	}
	return out, nil
}

func (c *WSClient) domainToBaseDN() string {
	// baseDN derivation in CLI is also domain->DN; in the library we can reuse the domain.
	parts := strings.Split(strings.TrimSpace(c.domain), ".")
	var b strings.Builder
	for i := 0; i < len(parts); i++ {
		p := strings.TrimSpace(parts[i])
		if p == "" {
			continue
		}
		if b.Len() > 0 {
			b.WriteString(",")
		}
		b.WriteString("DC=")
		b.WriteString(p)
	}
	return b.String()
}

func (c *WSClient) withAccountManagementClient(fn func(am *wscap.WSCapClient) error) error {
	if fn == nil {
		return fmt.Errorf("fn is required")
	}

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", c.dcFQDN, c.port), c.timeout)
	if err != nil {
		return fmt.Errorf("failed to connect to %s:%d: %w", c.dcFQDN, c.port, err)
	}

	targetSPN := c.buildTargetSPN(c.dcFQDN)
	nnsConn := c.newNNSConnection(conn, targetSPN)

	nmfConn := transport.NewNMFConnection(nnsConn, c.dcFQDN, c.port)
	if err := nmfConn.Connect(wscap.EndpointAccountManagement); err != nil {
		_ = nnsConn.Close()
		return fmt.Errorf("NMF connection failed for endpoint %s: %w", wscap.EndpointAccountManagement, err)
	}
	defer nnsConn.Close()

	am := wscap.NewWSCapClient(nmfConn, c.dcFQDN, c.port, wscap.EndpointAccountManagement, c.ldapPort, c.debugPrintXML)
	return fn(am)
}

func (c *WSClient) withAccountManagementClientResults(fn func(am *wscap.WSCapClient) ([]NameTranslateResult, error)) ([]NameTranslateResult, error) {
	if fn == nil {
		return nil, fmt.Errorf("fn is required")
	}

	var out []NameTranslateResult
	err := c.withAccountManagementClient(func(am *wscap.WSCapClient) error {
		res, err := fn(am)
		if err != nil {
			return err
		}
		out = res
		return nil
	})
	return out, err
}

// IMDAAttribute describes an attribute for an IMDA AddRequest.
//
// Name should be a fully qualified attribute type (e.g. "addata:cn", "addata:objectClass").
// XSIType should be an xsd:* type (e.g. "xsd:string", "xsd:int", "xsd:base64Binary").
// Values contains 1+ values for the attribute.
type IMDAAttribute struct {
	Name    string
	XSIType string
	Values  []string
}

// WSTransferCreateCustom creates a custom object via WS-Transfer ResourceFactory using an IMDA AddRequest.
//
// parentDN is the container DN; rdn is the relative distinguished name (e.g. "CN=MyObject").
// The required IMDA attributes ad:relativeDistinguishedName and ad:container-hierarchy-parent are always injected.
func (c *WSClient) WSTransferCreateCustom(parentDN, rdn string, attrs []IMDAAttribute) (string, error) {
	if !c.connected {
		return "", fmt.Errorf("not connected")
	}
	parentDN = strings.TrimSpace(parentDN)
	rdn = strings.TrimSpace(rdn)
	if parentDN == "" {
		return "", fmt.Errorf("parentDN is required")
	}
	if rdn == "" {
		return "", fmt.Errorf("rdn is required")
	}
	if len(attrs) == 0 {
		return "", fmt.Errorf("attrs is required")
	}

	soapAttrs := make([]soap.IMDAAttributeSpec, 0, len(attrs))
	for i := 0; i < len(attrs); i++ {
		a := attrs[i]
		name := strings.TrimSpace(a.Name)
		xsi := strings.TrimSpace(a.XSIType)
		if name == "" {
			return "", fmt.Errorf("attrs[%d].Name is required", i)
		}
		if xsi == "" {
			return "", fmt.Errorf("attrs[%d].XSIType is required", i)
		}
		if len(a.Values) == 0 {
			return "", fmt.Errorf("attrs[%d].Values is required", i)
		}
		soapAttrs = append(soapAttrs, soap.IMDAAttributeSpec{AttrType: name, XSIType: xsi, Values: a.Values})
	}

	return c.withEndpointWSTransferClient(wstransfer.EndpointResourceFactory, func(tx *wstransfer.WSTransferClient) (string, error) {
		return tx.CustomCreate(parentDN, rdn, soapAttrs)
	})
}

// ADCAPChangeOptionalFeature enables or disables an optional feature in a naming context.
func (c *WSClient) ADCAPChangeOptionalFeature(distinguishedName string, enable bool, featureID string) error {
	if !c.connected {
		return fmt.Errorf("not connected")
	}
	distinguishedName = strings.TrimSpace(distinguishedName)
	featureID = strings.TrimSpace(featureID)
	if distinguishedName == "" {
		return fmt.Errorf("distinguishedName is required")
	}
	if featureID == "" {
		return fmt.Errorf("featureID is required")
	}

	return c.withTopologyManagementClient(func(tm *wscap.WSCapClient) error {
		return tm.ChangeOptionalFeature(distinguishedName, enable, featureID)
	})
}

// ADCAPGetADDomain returns information about the domain containing the directory service.
func (c *WSClient) ADCAPGetADDomain() (*ADCAPActiveDirectoryDomain, error) {
	if !c.connected {
		return nil, fmt.Errorf("not connected")
	}
	var out *ADCAPActiveDirectoryDomain
	err := c.withTopologyManagementClient(func(tm *wscap.WSCapClient) error {
		res, err := tm.GetADDomain()
		if err != nil {
			return err
		}
		out = res
		return nil
	})
	return out, err
}

// ADCAPGetADForest returns information about the forest containing the directory service.
func (c *WSClient) ADCAPGetADForest() (*ADCAPActiveDirectoryForest, error) {
	if !c.connected {
		return nil, fmt.Errorf("not connected")
	}
	var out *ADCAPActiveDirectoryForest
	err := c.withTopologyManagementClient(func(tm *wscap.WSCapClient) error {
		res, err := tm.GetADForest()
		if err != nil {
			return err
		}
		out = res
		return nil
	})
	return out, err
}

// ADCAPGetVersion returns ADWS Custom Action Protocol version information.
func (c *WSClient) ADCAPGetVersion() (*ADCAPVersionInfo, error) {
	if !c.connected {
		return nil, fmt.Errorf("not connected")
	}
	var out *ADCAPVersionInfo
	err := c.withTopologyManagementClient(func(tm *wscap.WSCapClient) error {
		res, err := tm.GetVersion()
		if err != nil {
			return err
		}
		out = res
		return nil
	})
	return out, err
}

// ADCAPGetADDomainControllers returns info about domain controllers for the given nTDSDSA settings DNs.
func (c *WSClient) ADCAPGetADDomainControllers(ntdsSettingsDNs []string) ([]ADCAPActiveDirectoryDomainController, error) {
	if !c.connected {
		return nil, fmt.Errorf("not connected")
	}
	if len(ntdsSettingsDNs) == 0 {
		return nil, fmt.Errorf("at least one ntdsSettingsDN is required")
	}
	var out []ADCAPActiveDirectoryDomainController
	err := c.withTopologyManagementClient(func(tm *wscap.WSCapClient) error {
		res, err := tm.GetADDomainController(ntdsSettingsDNs)
		if err != nil {
			return err
		}
		out = res
		return nil
	})
	return out, err
}

func (c *WSClient) withTopologyManagementClient(fn func(tm *wscap.WSCapClient) error) error {
	if fn == nil {
		return fmt.Errorf("fn is required")
	}

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", c.dcFQDN, c.port), c.timeout)
	if err != nil {
		return fmt.Errorf("failed to connect to %s:%d: %w", c.dcFQDN, c.port, err)
	}

	targetSPN := c.buildTargetSPN(c.dcFQDN)
	nnsConn := c.newNNSConnection(conn, targetSPN)

	nmfConn := transport.NewNMFConnection(nnsConn, c.dcFQDN, c.port)
	if err := nmfConn.Connect(wscap.EndpointTopologyManagement); err != nil {
		_ = nnsConn.Close()
		return fmt.Errorf("NMF connection failed for endpoint %s: %w", wscap.EndpointTopologyManagement, err)
	}
	defer nnsConn.Close()

	tm := wscap.NewWSCapClient(nmfConn, c.dcFQDN, c.port, wscap.EndpointTopologyManagement, c.ldapPort, c.debugPrintXML)
	return fn(tm)
}
