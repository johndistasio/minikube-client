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
	kubeconfig "k8s.io/client-go/tools/clientcmd"
	kubeconfigapi "k8s.io/client-go/tools/clientcmd/api"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const kubeConfigPathDefault = "$KUBECONFIG, ~/.kube/config"
const caCertPathDefault = "~/.minikube/ca.crt"
const caKeyPathDefault = "~/.minikube/ca.key"
const notAfterDefault = int64(365 * 10)

var commit string
var version string

var kubeConfigPath = flag.String("kubeconfig", kubeConfigPathDefault, "path to kubeconfig file")
var caCertPath = flag.String("ca-cert", caCertPathDefault, "path to Minikube CA certificate")
var caKeyPath = flag.String("ca-key", caKeyPathDefault, "path to Minikube CA key")

var outPath = flag.String("out", "", "output path for client certificate and key")

var commonName = flag.String("cn", "", "client certificate CommonName")
var organization = flag.String("o", "", "client certificate Organization")
var notAfter = flag.Int64("not-after", notAfterDefault, "client certificate expiration, in days")

var showVersion = flag.Bool("version", false, "output version information and exit")

func parseCACertificate(cert io.Reader) (*x509.Certificate, error) {
	caCertBytes, err := ioutil.ReadAll(cert)

	if err != nil {
		return nil, err
	}

	caPem, _ := pem.Decode(caCertBytes)

	if caPem == nil {
		return nil, fmt.Errorf("invalid certificate format")
	}

	caCert, err := x509.ParseCertificate(caPem.Bytes)

	if err != nil {
		return nil, err
	}

	return caCert, nil
}

func parseCAKey(key io.Reader) (*rsa.PrivateKey, error) {
	caKeyBytes, err := ioutil.ReadAll(key)

	if err != nil {
		return nil, err
	}

	keyPem, _ := pem.Decode(caKeyBytes)

	if keyPem == nil {
		return nil, fmt.Errorf("invalid CA key format")
	}

	caKey, err := x509.ParsePKCS1PrivateKey(keyPem.Bytes)

	if err != nil {
		return nil, err
	}

	return caKey, nil
}

func dief(format string, v ...interface{}) {
	die(fmt.Sprintf(format, v...))
}

func die(message string) {
	_, _ = fmt.Println(message)
	os.Exit(1)
}

func resolveKubeConfigPath(home string, env string) string {
	var output string

	for _, path := range strings.Split(env, ":") {
		if path != "" {
			output = strings.Replace(path, "~", home, 1)
			output = strings.Replace(output, "$HOME", home, 1)
			break
		}
	}

	if output ==  "" {
		output = filepath.Join(home, ".kube/config")
	}

	return output
}

func main() {
	flag.Parse()

	if *showVersion {
		fmt.Printf("minikube-client: %s %s\n", version, commit)
		os.Exit(0)
	}

	if *commonName == "" || *organization == "" {
		die("Both -cn and -o are required")
	}

	home, err := os.UserHomeDir()

	if err != nil {
		dief("Fatal: %s", err.Error())
	}

	env := os.Getenv("KUBECONFIG")

	if *kubeConfigPath == kubeConfigPathDefault {
		*kubeConfigPath = resolveKubeConfigPath(home, env)
	}

	if *caCertPath == caCertPathDefault {
		*caCertPath = strings.Replace(caCertPathDefault, "~", home, 1)
	}

	if *caKeyPath == caKeyPathDefault {
		*caKeyPath = strings.Replace(caKeyPathDefault, "~", home, 1)
	}


	caCertFile, err := os.Open(*caCertPath)

	if err != nil {
		dief("Failed to open CA certificate: %s", err.Error())
	}

	defer caCertFile.Close()

	caCert, err := parseCACertificate(caCertFile)

	if err != nil {
		dief("Failed to parse CA certificate: %s", err.Error())
	}

	caKeyFile, err := os.Open(*caKeyPath)

	if err != nil {
		dief("Failed to open CA key: %s", err.Error())
	}

	defer caKeyFile.Close()

	caKey, err := parseCAKey(caKeyFile)

	if err != nil {
		dief("Failed to parse CA key: %s", err.Error())
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
		NotAfter:    time.Now().Add(time.Hour * 24 * time.Duration(*notAfter)),
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

	if *outPath != "" {
		*outPath = filepath.Clean(*outPath)

		certPath := filepath.Join(*outPath, *commonName + ".crt")
		keyPath := filepath.Join(*outPath, *commonName + ".key")

		err = ioutil.WriteFile(certPath, certPem.Bytes(), 0755)

		if err != nil {
			dief("Failed to write certificate: %s", err.Error())
		}

		err = ioutil.WriteFile(keyPath, keyPem.Bytes(), 0600)

		if err != nil {
			_ = os.Remove(certPath)
			dief("Failed to write private key: %s", err.Error())
		}

		fmt.Printf("Wrote certificate and key to %s\n", *outPath)
	} else {
		config, err := kubeconfig.LoadFromFile(*kubeConfigPath)

		if err != nil {
			dief("Failed to load kubeconfig: %s", err.Error())
		}

		config.AuthInfos[*commonName] = &kubeconfigapi.AuthInfo{
			ClientCertificateData: certPem.Bytes(),
			ClientKeyData:         keyPem.Bytes(),
		}

		err = kubeconfig.WriteToFile(*config, *kubeConfigPath)

		if err != nil {
			die(err.Error())
		}

		fmt.Printf("Added certificate and key to %s\n", *kubeConfigPath)
	}
}
