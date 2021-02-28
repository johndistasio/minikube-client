package internal

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var ErrCertificate = errors.New("failed to read CA certificate")
var ErrKey = errors.New("failed to read CA key")

func OpenCA(caCertPath string, caKeyPath string) (*x509.Certificate, *rsa.PrivateKey, error) {
	cert, err := openCACertificate(caCertPath)

	if err != nil {
		return nil, nil, err
	}

	key, err := openCAKey(caKeyPath)

	if err != nil {
		return nil, nil, err
	}

	return cert, key, nil
}

func openCACertificate(caCertPath string) (*x509.Certificate, error) {
	cert, err := os.Open(caCertPath)

	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrCertificate, err.Error())
	}

	defer cert.Close()

	caCertBytes, err := ioutil.ReadAll(cert)

	if err != nil {
		return nil, err
	}

	caPem, _ := pem.Decode(caCertBytes)

	if caPem == nil {
		return nil, fmt.Errorf("%w: invalid certificate format", ErrCertificate)
	}

	caCert, err := x509.ParseCertificate(caPem.Bytes)

	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrCertificate, err.Error())
	}

	return caCert, nil
}

func openCAKey(caKeyPath string) (*rsa.PrivateKey, error) {
	key, err := os.Open(caKeyPath)

	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrKey, err.Error())
	}

	defer key.Close()

	caKeyBytes, err := ioutil.ReadAll(key)

	if err != nil {
		return nil, err
	}

	keyPem, _ := pem.Decode(caKeyBytes)

	if keyPem == nil {
		return nil, fmt.Errorf("%w: invalid CA key format", ErrKey)
	}

	caKey, err := x509.ParsePKCS1PrivateKey(keyPem.Bytes)

	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrKey, err.Error())
	}

	return caKey, nil
}

func ResolveKubeConfigPath(home string, env string) string {
	var output string

	for _, path := range strings.Split(env, ":") {
		if path != "" {
			output = strings.Replace(path, "~", home, 1)
			output = strings.Replace(output, "$HOME", home, 1)
			break
		}
	}

	if output == "" {
		output = filepath.Join(home, ".kube/config")
	}

	return output
}

type Options struct {
	CommonName   string
	Organization string
	NotAfter     time.Time
	KeyBits      int
	CACert       *x509.Certificate
	CAKey        *rsa.PrivateKey
}

func GenerateSignedCertAndKey(options Options) ([]byte, []byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, options.KeyBits)

	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %s", err.Error())
	}

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject: pkix.Name{
			CommonName:   options.CommonName,
			Organization: strings.Split(options.Organization, ","),
		},
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter: options.NotAfter,
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, options.CACert, key.Public(), options.CAKey)

	if err != nil {
		return nil, nil, fmt.Errorf("failed to sign certificate: %s", err.Error())
	}

	certPem := &bytes.Buffer{}

	if err := pem.Encode(certPem, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes}); err != nil {
		return nil, nil, fmt.Errorf("failed to encode certificate: %s", err.Error())
	}

	keyPem := &bytes.Buffer{}

	if err := pem.Encode(keyPem, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}); err != nil {
		return nil, nil, fmt.Errorf("failed to encode private key: %s", err.Error())
	}

	return certPem.Bytes(), keyPem.Bytes(), nil
}
