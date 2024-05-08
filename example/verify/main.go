package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"log"
	"os"

	certparser "github.com/salrashid123/gcp-tpm/parser"
)

var (
	// projectID = flag.String("projectID", "yourproject", "ProjectID")
	// zone      = flag.String("zone", "us-central1-a", "Zone")
	// vmId      = flag.String("vmId", "instance-1", "VM Instance name")

	akCert = flag.String("akCert", "../certs/akcert.pem", "rootsCA")
	rootCA = flag.String("rootCA", "../certs/ak_root.pem", "rootsCA")

	intermediateCA = flag.String("intermediateCA", "../certs/ak_intermediate.pem", "intermediate CA")

	signature  = flag.String("signature", "krLYr99i6qTlB+UZ1bQ0pJUPooWW7IQD7lQ+5Fp+pmEp47UnBMK+TZkeH7ATGeVrXYY4bsPix/+f8p1DoTXObcSQZVZNdEEsBofCKULkUKZ5doggtl17zNWzKnjl6jjIr7criEOLRNZXVQZR/AckBZQIWWZ7ZO8unaHkoOXWlF6CIUdOaYIm0nuPGRrwmL5G15CTAUGeudIwMJBb7qZt2WaTyPddeUOzN4KsEuRfYXQpeRUNfcTcNMPiZENj5fNEUybviOTb8XW05e2ZhdD4DFBVyzaZ9lK3VnYICDHfWngnipO3LMWC+aJjei1C2CVnuHvhEsNPxdFDQfh5NPQ53w", "base64 encoded signature")
	dataSigned = flag.String("dataSigned", "foobar", "data that was signed")
)

func main() {

	flag.Parse()

	// usging API
	// ctx := context.Background()

	// computeService, err := compute.NewService(ctx)
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// ekKeys, err := computeService.Instances.GetShieldedInstanceIdentity(*projectID, *zone, *vmId).Do()
	// if err != nil {
	// 	log.Fatalf("Unable to find  Instance %v", err)
	// }
	//pubEKey := ekKeys.EncryptionKey.EkPub
	//pubECert := ekKeys.EncryptionKey.EkCert
	//pubSKey := ekKeys.SigningKey.EkPub
	//pubSCert := ekKeys.SigningKey.EkCert

	// read AK cert from file

	akPEM, err := os.ReadFile(*akCert)
	if err != nil {
		log.Fatal(err)
	}

	block, _ := pem.Decode([]byte(akPEM))
	if block == nil {
		log.Fatal(err)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	e, err := certparser.GetInstanceInfo(cert)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("VM InstanceName from AK cert: ", e.InstanceName)

	log.Println("Verify with EKcert with chain")

	rootPEM, err := os.ReadFile(*rootCA)
	if err != nil {
		log.Fatal(err)
	}

	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM([]byte(rootPEM))
	if !ok {
		log.Fatal(err)
	}

	var exts []asn1.ObjectIdentifier
	for _, ext := range cert.UnhandledCriticalExtensions {
		if ext.Equal(certparser.OidExtensionSubjectAltName) {
			continue
		}
		exts = append(exts, ext)
	}
	cert.UnhandledCriticalExtensions = exts

	intermediatePEM, err := os.ReadFile(*intermediateCA)
	if err != nil {
		log.Fatal(err)
	}

	intermediates := x509.NewCertPool()
	ok = intermediates.AppendCertsFromPEM([]byte(intermediatePEM))
	if !ok {
		log.Fatal(err)
	}

	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsage(x509.ExtKeyUsageAny)},
	}
	if _, err := cert.Verify(opts); err != nil {
		log.Fatalf("failed to verify certificate: " + err.Error())
	}
	log.Printf("Verified Certificate Chain")

	log.Printf("Verifying signature %s\n", *signature)

	aKdataToVerify := []byte(*dataSigned)

	h := sha256.New()
	h.Write(aKdataToVerify)

	b, err := base64.RawStdEncoding.DecodeString(*signature)
	if err != nil {
		log.Fatalf("Error decoding %v\n", err)
	}
	if err := rsa.VerifyPKCS1v15(cert.PublicKey.(*rsa.PublicKey), crypto.SHA256, h.Sum(nil), b); err != nil {
		log.Printf("ERROR:  could  VerifyPKCS1v15 (signing): %v", err)
		return
	}
	log.Printf("     Signature Verified")

}
