package gss

import (
	"strings"
	"testing"

	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultKerberosConfig(t *testing.T) {
	t.Parallel()

	contents, err := defaultKerberosConfig("eu.example.com", "dc1.eu.example.com:88")
	require.NoError(t, err)
	assert.Contains(t, contents, "default_realm = EU.EXAMPLE.COM")
	assert.Contains(t, contents, "kdc = dc1.eu.example.com:88")
	_, err = config.NewFromString(contents)
	assert.NoError(t, err)
}

func TestDefaultKerberosConfigRejectsNewlines(t *testing.T) {
	t.Parallel()

	_, err := defaultKerberosConfig("EU.EXAMPLE.COM", "dc1.example.com:88\n[other]")
	assert.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "newlines"))
}
