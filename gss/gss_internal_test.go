package gss

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateTKEYName(t *testing.T) {
	t.Parallel()

	tkey, err := generateTKEYName("host.example.com")
	require.NoError(t, err)
	assert.Regexp(t, `^\d+\.sig-host\.example\.com\.$`, tkey)
}

func TestGenerateSPN(t *testing.T) {
	t.Parallel()

	spn := generateSPN("host.example.com")
	assert.Equal(t, "DNS/host.example.com", spn)

	spn = generateSPN("host.example.com.")
	assert.Equal(t, "DNS/host.example.com", spn)
}

func TestWrapGSSStage(t *testing.T) {
	t.Parallel()

	err := wrapGSSStage("getting service ticket for DNS/ns.example.com", errors.New("KRB_AP_ERR_MODIFIED"))
	require.Error(t, err)
	assert.EqualError(t, err, "GSS-TSIG getting service ticket for DNS/ns.example.com: KRB_AP_ERR_MODIFIED")
}
