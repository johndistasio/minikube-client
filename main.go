package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const caCertPathDefault = "~/.minikube/ca.crt"
const caKeyPathDefault = "~/.minikube/ca.key"
const certOutDefault = "./cert.pem"
const keyOutDefault = "./key.pem"

var revision string

var caCertPath = flag.String("ca-cert", caCertPathDefault, "path to Minikube CA certificate")
var caKeyPath = flag.String("ca-key", caKeyPathDefault, "path to Minikube CA key")

var certPath = flag.String("cert", certOutDefault, "output path for client certificate")
var keyPath = flag.String("key", keyOutDefault, "output path for client private key")

var commonName = flag.String("cn", "", "client certificate CommonName")
var organization = flag.String("o", "", "client certificate Organization")

var version = flag.Bool("version", false, "version information")

func parseCACertificate(cert io.Reader) (*x509.Certificate, error) {
	caCertBytes, err := ioutil.ReadAll(cert)

	if err != nil {
		return nil, fmt.Errorf("Failed to read CA certificate: %s\n", err.Error())
	}

	caPem, _ := pem.Decode(caCertBytes)

	if caPem == nil {
		return nil, fmt.Errorf("Invalid CA certificate format\n")
	}

	caCert, err := x509.ParseCertificate(caPem.Bytes)

	if err != nil {
		return nil, fmt.Errorf("Failed to parse CA certificate: %s\n", err.Error())
	}

	return caCert, nil
}

func parseCAKey(key io.Reader) (*rsa.PrivateKey, error) {
	caKeyBytes, err := ioutil.ReadAll(key)

	if err != nil {
		return nil, fmt.Errorf("Failed to read CA key: %s\n", err.Error())
	}

	keyPem, _ := pem.Decode(caKeyBytes)

	if keyPem == nil {
		return nil, fmt.Errorf("Invalid CA key format\n")
	}

	caKey, err := x509.ParsePKCS1PrivateKey(keyPem.Bytes)

	if err != nil {
		return nil, fmt.Errorf("Failed to parse CA key: %s\n", err.Error())
	}

	return caKey, nil
}

func dief(format string, v ...interface{}) {
	die(fmt.Sprintf(format, v))
}

func die(message string) {
	_, _ = fmt.Println(message)
	os.Exit(1)
}

func main() {
	flag.Parse()

	if *version {
		fmt.Printf("minikube-client: %s\n", revision)
		os.Exit(0)
	}

	if *commonName == "" || *organization == "" {
		die("Invalid input: CommonName and Organization are required.")
	}

	if *caCertPath == caCertPathDefault || *caKeyPath == caKeyPathDefault {
		home, err := os.UserHomeDir()

		if err != nil {
			die(fmt.Sprintf("Fatal: %s", err.Error()))
		}

		home = filepath.Clean(home)

		if *caCertPath == caCertPathDefault {
			*caCertPath = strings.Replace(caCertPathDefault, "~", home, 1)
		}

		if *caKeyPath == caKeyPathDefault {
			*caKeyPath = strings.Replace(caKeyPathDefault, "~", home, 1)
		}
	}

	caCertFile, err := os.Open(*caCertPath)

	if err != nil {
		dief("Failed to open CA certificate: %s", err.Error())
	}

	defer caCertFile.Close()

	caCert, err := parseCACertificate(caCertFile)

	if err != nil {
		_, _ = fmt.Fprint(os.Stderr, err.Error())
		os.Exit(1)
	}

	caKeyFile, err := os.Open(*caKeyPath)

	if err != nil {
		dief("Failed to open CA key: %s", err.Error())
	}

	defer caKeyFile.Close()

	caKey, err := parseCAKey(caKeyFile)

	if err != nil {
		die(err.Error())
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)

	if err != nil {
		dief("Private key generation error: %s", err.Error())
	}

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject: pkix.Name{
			CommonName:   *commonName,
			Organization: strings.Split(*organization, ","),
		},
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter:    time.Now().Add(time.Hour * 24 * 365 * 10),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, caCert, key.Public(), caKey)

	if err != nil {
		dief("Failed to sign certificate: %s", err.Error())
	}

	certPem := &bytes.Buffer{}

	if err := pem.Encode(certPem, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes}); err != nil {
		dief("Failed to encode certificate: %s", err.Error())
	}

	keyPem := &bytes.Buffer{}

	if err := pem.Encode(keyPem, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}); err != nil {
		dief("Failed to encode private key: %s", err.Error())
	}

	err = ioutil.WriteFile(*certPath, certPem.Bytes(), 0755)

	if err != nil {
		dief("Failed to write certificate: %s\n", err.Error())
	}

	err = ioutil.WriteFile(*keyPath, keyPem.Bytes(), 0600)

	if err != nil {
		dief("Failed to write private key: %s\n", err.Error())
	}
}
