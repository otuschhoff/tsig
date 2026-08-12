//go:build windows
// +build windows

package gss

import (
	"encoding/hex"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/alexbrainman/sspi"
	"github.com/alexbrainman/sspi/negotiate"
	wrapper "github.com/bodgit/gssapi"
	"github.com/bodgit/tsig"
	"github.com/bodgit/tsig/internal/util"
	"github.com/go-logr/logr"
	multierror "github.com/hashicorp/go-multierror"
	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/miekg/dns"
)

type windowsContext interface {
	generate([]byte) ([]byte, error)
	verify([]byte, []byte) error
	expiry() time.Time
	close() error
}

type sspiContext struct {
	ctx *negotiate.ClientContext
}

func (ctx *sspiContext) generate(msg []byte) ([]byte, error) {
	return ctx.ctx.MakeSignature(msg, 0, 0)
}

func (ctx *sspiContext) verify(stripped, mac []byte) error {
	_, err := ctx.ctx.VerifySignature(stripped, mac, 0)

	return err
}

func (ctx *sspiContext) expiry() time.Time {
	return ctx.ctx.Expiry()
}

func (ctx *sspiContext) close() error {
	return ctx.ctx.Release()
}

type keytabContext struct {
	ctx *wrapper.Initiator
}

func (ctx *keytabContext) generate(msg []byte) ([]byte, error) {
	return ctx.ctx.MakeSignature(msg)
}

func (ctx *keytabContext) verify(stripped, mac []byte) error {
	return ctx.ctx.VerifySignature(stripped, mac)
}

func (ctx *keytabContext) expiry() time.Time {
	return ctx.ctx.Expiry()
}

func (ctx *keytabContext) close() error {
	return ctx.ctx.Close()
}

// Client maps the TKEY name to the context that negotiated it as
// well as any other internal state.
type Client struct {
	m      sync.RWMutex
	client *dns.Client
	config string
	ctx    map[string]windowsContext
	logger logr.Logger
}

// WithConfig sets the Kerberos configuration used.
func WithConfig(config string) func(*Client) error {
	return func(c *Client) error {
		c.config = config

		return nil
	}
}

// NewClient performs any library initialization necessary.
// It returns a context handle for any further functions along with any error
// that occurred.
func NewClient(dnsClient *dns.Client, options ...func(*Client) error) (*Client, error) {
	client, err := util.CopyDNSClient(dnsClient)
	if err != nil {
		return nil, err
	}

	client.TsigProvider = new(gssNoVerify)

	c := &Client{
		client: client,
		ctx:    make(map[string]windowsContext),
		logger: logr.Discard(),
	}

	if err := c.setOption(options...); err != nil {
		return nil, err
	}

	return c, nil
}

// Close deletes any active contexts and unloads any underlying libraries as
// necessary.
// It returns any error that occurred.
func (c *Client) Close() error {
	return c.close()
}

func (c *Client) generate(ctx windowsContext, msg []byte) ([]byte, error) {
	return ctx.generate(msg)
}

func (c *Client) verify(ctx windowsContext, stripped, mac []byte) error {
	return ctx.verify(stripped, mac)
}

func (c *Client) negotiateContext(host string, creds *sspi.Credentials) (string, time.Time, error) {
	hostname, _, err := net.SplitHostPort(host)
	if err != nil {
		return "", time.Time{}, err
	}

	keyname, err := generateTKEYName(hostname)
	if err != nil {
		return "", time.Time{}, err
	}

	ctx, output, err := negotiate.NewClientContext(creds, generateSPN(hostname))
	if err != nil {
		return "", time.Time{}, err
	}

	var (
		completed bool
		tkey      *dns.TKEY
	)

	for ok := false; !ok; ok = completed {
		//nolint:lll
		if tkey, _, err = util.ExchangeTKEY(c.client, host, keyname, tsig.GSS, util.TkeyModeGSS, 3600, output, nil, "", ""); err != nil {
			return "", time.Time{}, multierror.Append(err, ctx.Release())
		}

		if tkey.Header().Name != keyname {
			return "", time.Time{}, multierror.Append(errDoesNotMatch, ctx.Release())
		}

		input, err := hex.DecodeString(tkey.Key)
		if err != nil {
			return "", time.Time{}, multierror.Append(err, ctx.Release())
		}

		if completed, output, err = ctx.Update(input); err != nil {
			return "", time.Time{}, multierror.Append(err, ctx.Release())
		}
	}

	c.m.Lock()
	defer c.m.Unlock()

	c.ctx[keyname] = &sspiContext{ctx: ctx}

	return keyname, ctx.Expiry(), nil
}

func (c *Client) negotiateContextWithKeytab(host, domain, username, path string) (string, time.Time, error) {
	hostname, _, err := net.SplitHostPort(host)
	if err != nil {
		return "", time.Time{}, err
	}

	config := c.config
	if config == "" {
		config, err = defaultKerberosConfig(domain, net.JoinHostPort(hostname, "88"))
		if err != nil {
			return "", time.Time{}, err
		}
	}

	realm := strings.ToUpper(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	options := []wrapper.Option[wrapper.Initiator]{
		wrapper.WithConfig[wrapper.Initiator](config),
		wrapper.WithDomain[wrapper.Initiator](realm),
		wrapper.WithUsername[wrapper.Initiator](username),
		wrapper.WithKeytab[wrapper.Initiator](path),
		wrapper.WithLogger[wrapper.Initiator](c.logger),
	}

	ctx, err := wrapper.NewInitiator(options...)
	if err != nil {
		return "", time.Time{}, err
	}

	closeWithError := func(err error) (string, time.Time, error) {
		return "", time.Time{}, multierror.Append(err, ctx.Close()).ErrorOrNil()
	}

	keyname, err := generateTKEYName(hostname)
	if err != nil {
		return closeWithError(err)
	}

	spn := generateSPN(hostname)
	flags := gssapi.ContextFlagMutual | gssapi.ContextFlagReplay | gssapi.ContextFlagInteg
	output, cont, err := ctx.Initiate(spn, flags, nil)
	if err != nil {
		return closeWithError(err)
	}

	for cont {
		tkey, _, err := util.ExchangeTKEY(c.client, host, keyname, tsig.GSS, util.TkeyModeGSS, 3600, output, nil, "", "")
		if err != nil {
			return closeWithError(err)
		}
		if tkey.Header().Name != keyname {
			return closeWithError(errDoesNotMatch)
		}

		input, err := hex.DecodeString(tkey.Key)
		if err != nil {
			return closeWithError(err)
		}
		output, cont, err = ctx.Initiate(spn, flags, input)
		if err != nil {
			return closeWithError(err)
		}
	}

	c.m.Lock()
	defer c.m.Unlock()

	c.ctx[keyname] = &keytabContext{ctx: ctx}

	return keyname, ctx.Expiry(), nil
}

// NegotiateContext exchanges RFC 2930 TKEY records with the indicated DNS
// server to establish a security context using the current user.
// It returns the negotiated TKEY name, expiration time, and any error that
// occurred.
func (c *Client) NegotiateContext(host string) (keyname string, expiry time.Time, err error) {
	creds, err := negotiate.AcquireCurrentUserCredentials()
	if err != nil {
		return "", time.Time{}, err
	}

	defer func() {
		err = multierror.Append(err, creds.Release()).ErrorOrNil()
	}()

	return c.negotiateContext(host, creds)
}

// NegotiateContextWithCredentials exchanges RFC 2930 TKEY records with the
// indicated DNS server to establish a security context using the provided
// credentials.
// It returns the negotiated TKEY name, expiration time, and any error that
// occurred.
//
//nolint:lll
func (c *Client) NegotiateContextWithCredentials(host, domain, username, password string) (keyname string, expiry time.Time, err error) {
	creds, err := negotiate.AcquireUserCredentials(domain, username, password)
	if err != nil {
		return "", time.Time{}, err
	}

	defer func() {
		err = multierror.Append(err, creds.Release()).ErrorOrNil()
	}()

	return c.negotiateContext(host, creds)
}

// NegotiateContextWithKeytab exchanges RFC 2930 TKEY records with the
// indicated DNS server to establish a security context using the provided
// keytab.
// It returns the negotiated TKEY name, expiration time, and any error that
// occurred.
func (c *Client) NegotiateContextWithKeytab(host, domain, username, path string) (string, time.Time, error) {
	return c.negotiateContextWithKeytab(host, domain, username, path)
}

// DeleteContext deletes the active security context associated with the given
// TKEY name.
// It returns any error that occurred.
func (c *Client) DeleteContext(keyname string) error {
	c.m.Lock()
	defer c.m.Unlock()

	ctx, ok := c.ctx[keyname]
	if !ok {
		return errNoSuchContext
	}

	if err := ctx.close(); err != nil {
		return err
	}

	delete(c.ctx, keyname)

	return nil
}
