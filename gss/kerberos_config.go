package gss

import (
	"fmt"
	"strings"
)

func defaultKerberosConfig(domain, kdc string) (string, error) {
	realm := strings.ToUpper(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	kdc = strings.TrimSpace(kdc)
	if realm == "" || kdc == "" {
		return "", fmt.Errorf("Kerberos realm and KDC must not be empty")
	}
	if strings.ContainsAny(realm+kdc, "\r\n") {
		return "", fmt.Errorf("Kerberos realm and KDC must not contain newlines")
	}

	dnsDomain := strings.ToLower(realm)

	return fmt.Sprintf(`[libdefaults]
 default_realm = %s
 dns_lookup_kdc = false
 rdns = false
 udp_preference_limit = 1

[realms]
 %s = {
  kdc = %s
 }

[domain_realm]
 .%s = %s
 %s = %s
`, realm, realm, kdc, dnsDomain, realm, dnsDomain, realm), nil
}
