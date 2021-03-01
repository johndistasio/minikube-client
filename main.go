package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	kubeconfig "k8s.io/client-go/tools/clientcmd"
	kubeconfigapi "k8s.io/client-go/tools/clientcmd/api"

	"github.com/johndistasio/minikube-client/internal"
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

func main() {
	log.SetFlags(0)
	flag.Parse()

	if *showVersion {
		log.Printf("minikube-client: %s %s\n", version, commit)
		os.Exit(0)
	}

	if *commonName == "" || *organization == "" {
		log.Fatal("both -cn and -o are required")
	}

	home, err := os.UserHomeDir()

	if err != nil {
		log.Fatalf("failed to determine home directory: %s", err.Error())
	}

	env := os.Getenv("KUBECONFIG")

	if *kubeConfigPath == kubeConfigPathDefault {
		*kubeConfigPath = internal.ResolveKubeConfigPath(home, env)
	}

	if *caCertPath == caCertPathDefault {
		*caCertPath = strings.Replace(caCertPathDefault, "~", home, 1)
	}

	if *caKeyPath == caKeyPathDefault {
		*caKeyPath = strings.Replace(caKeyPathDefault, "~", home, 1)
	}

	caCert, caKey, err := internal.OpenCA(*caCertPath, *caKeyPath)

	if err != nil {
		log.Fatal(err.Error())
	}

	options := internal.Options{
		CommonName:   *commonName,
		Organization: *organization,
		NotAfter:     time.Now().Add(time.Hour * 24 * time.Duration(*notAfter)),
		KeyBits:      2028,
		CACert:       caCert,
		CAKey:        caKey,
	}

	certPem, keyPem, err := internal.GenerateSignedCertAndKey(options)

	if err != nil {
		log.Fatal(err.Error())
	}

	if *outPath != "" {
		*outPath, err = filepath.Abs(*outPath)

		if err != nil {
			log.Fatalf("failed to determine output path: %s", err.Error())
		}

		certPath := filepath.Join(*outPath, *commonName+".crt")
		keyPath := filepath.Join(*outPath, *commonName+".key")

		err = ioutil.WriteFile(certPath, certPem, 0755)

		if err != nil {
			log.Fatalf("failed to write certificate: %s", err.Error())
		}

		err = ioutil.WriteFile(keyPath, keyPem, 0600)

		if err != nil {
			_ = os.Remove(certPath)
			log.Fatalf("failed to write private key: %s", err.Error())
		}

		fmt.Printf("wrote certificate and key to %s\n", *outPath)
	} else {
		config, err := kubeconfig.LoadFromFile(*kubeConfigPath)

		if err != nil {
			log.Fatalf("failed to load kubeconfig: %s", err.Error())
		}

		config.AuthInfos[*commonName] = &kubeconfigapi.AuthInfo{
			ClientCertificateData: certPem,
			ClientKeyData:         keyPem,
		}

		err = kubeconfig.WriteToFile(*config, *kubeConfigPath)

		if err != nil {
			log.Fatal(err.Error())
		}

		fmt.Printf("added certificate and key to %s\n", *kubeConfigPath)
	}
}
