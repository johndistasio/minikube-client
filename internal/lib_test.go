package internal

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestResolveKubeConfigPath_Default(t *testing.T) {
	home := "/home/test"

	env := ""

	expected := filepath.Join(home, ".kube/config")

	actual := ResolveKubeConfigPath(home, env)

	if expected != actual {
		t.Errorf("Incorrectly resolved \"~/.kube/config\"; expected \"%s\" got \"%s\"", expected, actual)
	}
}

func TestResolveKubeConfigPath_KUBECONFIG_Tilde(t *testing.T) {
	home := "/home/test"

	env := "~/kube-config"

	expected := filepath.Join(home, "kube-config")

	actual := ResolveKubeConfigPath(home, env)

	if expected != actual {
		t.Errorf("Incorrectly resolved \"~\" in \"$KUBECONFIG\"; expected \"%s\" got \"%s\"", expected, actual)
	}
}

func TestResolveKubeConfigPath_KUBECONFIG_Var(t *testing.T) {
	home := "/home/test"

	env := "$HOME/dir/.kube/config"

	expected := filepath.Join(home, "dir/.kube/config")

	actual := ResolveKubeConfigPath(home, env)

	if expected != actual {
		t.Errorf("Incorrectly resolved \"$HOME\" in \"$KUBECONFIG\"; expected \"%s\" got \"%s\"", expected, actual)
	}
}

func TestGenerateSignedCertAndKey(t *testing.T) {
	// first we have to set up a dummy ca

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)

	if err != nil {
		t.Fatal(err)
	}

	caTemplate := &x509.Certificate{
		IsCA:                  true,
		BasicConstraintsValid: true,

		Subject:      pkix.Name{CommonName: "testCA"},
		SerialNumber: big.NewInt(time.Now().Unix()),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour * 24 * 365),
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caKey.Public(), caKey)

	if err != nil {
		t.Fatal(err)
	}

	caCert, err := x509.ParseCertificate(caBytes)

	if err != nil {
		t.Fatal(err)
	}

	certPool := x509.NewCertPool()
	certPool.AddCert(caCert)

	// now actually set up our test

	cn := "testCN"
	o := []string{"testO1", "testO2"}

	// this needs to be:
	// A) set reasonably far ahead into the future that it doesn't expire before we evaluate it later; and
	// B) truncated down to the second to match the formatted applied during cert creation
	notAfter := time.Now().Add(time.Hour).UTC().Truncate(time.Second)

	options := Options{
		CommonName:   cn,
		Organization: strings.Join(o, ","),
		NotAfter:     notAfter,
		KeyBits:      2028,
		CACert:       caCert,
		CAKey:        caKey,
	}

	cert, key, err := GenerateSignedCertAndKey(options)

	if err != nil {
		t.Fatal(err)
	}

	certPem, _ := pem.Decode(cert)

	if certPem == nil {
		t.Fatal("certificate is not in PEM format")
	}

	keyPem, _ := pem.Decode(key)

	if keyPem == nil {
		t.Fatal("key is not in PEM format")
	}

	parsedCert, err := x509.ParseCertificate(certPem.Bytes)

	if err != nil {
		t.Fatal("certificate is not a valid x509 certificate")
	}

	parsedKey, err := x509.ParsePKCS1PrivateKey(keyPem.Bytes)

	if err != nil {
		t.Fatal("key is not an rsa private key")
	}

	if !parsedKey.PublicKey.Equal(parsedCert.PublicKey) {
		t.Error("certificate and key do not match")
	}

	if _, err := parsedCert.Verify(x509.VerifyOptions{Roots: certPool}); err != nil {
		t.Error("certificate not signed by provided CA")
	}

	if parsedCert.Subject.CommonName != cn {
		t.Errorf("certificate uses incorrect CommonName \"%s\"", parsedCert.Subject.CommonName)
	}

	if parsedCert.NotAfter != notAfter {
		t.Errorf("certificate uses incorrect NotAfter: \"%s\", expected: \"%s\"",
			parsedCert.NotAfter.String(), notAfter.String())
	}

	for _, actual := range parsedCert.Subject.Organization {

		found := false

		for _, expected := range o {
			if actual == expected {
				found = true
				break
			}
		}

		if !found {
			t.Errorf("certificate specifies incorrect Organization: %s", actual)
		}
	}

	actualOrgs := len(parsedCert.Subject.Organization)
	expectedOrgs := len(o)

	if actualOrgs != expectedOrgs {
		t.Errorf("certificate specifies %d Organizations, expected %d", actualOrgs, expectedOrgs)
	}
}