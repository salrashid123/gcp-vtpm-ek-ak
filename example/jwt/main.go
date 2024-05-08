package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"

	jwt "github.com/golang-jwt/jwt/v5"
	tpmjwt "github.com/salrashid123/golang-jwt-tpm"
)

// [go-tpm-tools/client](https://pkg.go.dev/github.com/google/go-tpm-tools/client#pkg-constants)

// // AK (signing)
// GceAKCertNVIndexRSA     uint32 = 0x01c10000
// // EK (encryption)
// EKCertNVIndexRSA uint32 = 0x01c00002

const (
	tpmDevice             = "/dev/tpm0"
	signCertNVIndex       = 0x01c10000
	signKeyNVIndex        = 0x01c10001
	encryptionCertNVIndex = 0x01c00002
	emptyPassword         = ""
)

var (
	handleNames = map[string][]tpm2.HandleType{
		"all":       []tpm2.HandleType{tpm2.HandleTypeLoadedSession, tpm2.HandleTypeSavedSession, tpm2.HandleTypeTransient},
		"loaded":    []tpm2.HandleType{tpm2.HandleTypeLoadedSession},
		"saved":     []tpm2.HandleType{tpm2.HandleTypeSavedSession},
		"transient": []tpm2.HandleType{tpm2.HandleTypeTransient},
	}

	tpmPath = flag.String("tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket).")
)

func main() {

	flag.Parse()
	log.Println("======= Init  ========")

	rwc, err := tpm2.OpenTPM(*tpmPath)
	if err != nil {
		log.Fatalf("can't open TPM %q: %v", tpmPath, err)
	}

	totalHandles := 0
	for _, handleType := range handleNames["all"] {
		handles, err := client.Handles(rwc, handleType)
		if err != nil {
			log.Fatalf("getting handles: %v", err)
		}
		for _, handle := range handles {
			if err = tpm2.FlushContext(rwc, handle); err != nil {
				log.Fatalf("flushing handle 0x%x: %v", handle, err)
			}
			log.Printf("Handle 0x%x flushed\n", handle)
			totalHandles++
		}
	}

	log.Printf("%d handles flushed\n", totalHandles)

	// *****************

	log.Printf("     Load SigningKey and Cert ")
	// read direct from nv template
	kk, err := client.EndorsementKeyFromNvIndex(rwc, client.GceAKTemplateNVIndexRSA)
	// just just do this
	//kk, err := client.AttestationKeyRSA(rwc)
	if err != nil {
		log.Printf("ERROR:  could not get EndorsementKeyFromNvIndex: %v", err)
		return
	}
	defer kk.Close()

	pubKey := kk.PublicKey().(*rsa.PublicKey)
	akBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		log.Printf("ERROR:  could not get MarshalPKIXPublicKey: %v", err)
		return
	}
	akPubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: akBytes,
		},
	)
	log.Printf("     Signing PEM \n%s", string(akPubPEM))

	certASN1, err := tpm2.NVReadEx(rwc, tpmutil.Handle(client.GceAKCertNVIndexRSA), tpm2.HandleOwner, "", 0)
	if err != nil {
		log.Printf("ERROR:  error reading AK Certificate from NV: %v", err)
		return
	}
	signCert, err := x509.ParseCertificate(certASN1)
	if err != nil {
		log.Printf("ERROR:  error sparsing AK singing cert : %v", err)
		return
	}

	akCertPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: signCert.Raw,
		},
	)
	log.Printf("     Signing Certificate \n%s", string(akCertPEM))

	//r, err := kk.GetSigner()

	// ******************

	ctx := context.Background()
	claims := &jwt.RegisteredClaims{
		ExpiresAt: &jwt.NumericDate{time.Now().Add(time.Minute * 10)},
		Issuer:    "test",
	}

	tpmjwt.SigningMethodTPMRS256.Override()
	token := jwt.NewWithClaims(tpmjwt.SigningMethodTPMRS256, claims)

	config := &tpmjwt.TPMConfig{
		TPMDevice: rwc,
		Key:       kk,
		KeyID:     "Jp0no8s4Dp0kw58LyfIizoST/cBki1/KNqBxDKxC5sQ=",
	}

	keyctx, err := tpmjwt.NewTPMContext(ctx, config)
	if err != nil {
		log.Fatalf("Unable to initialize tpmJWT: %v", err)
	}

	token.Header["kid"] = config.GetKeyID()
	tokenString, err := token.SignedString(keyctx)
	if err != nil {
		log.Fatalf("Error signing %v", err)
	}
	fmt.Printf("TOKEN: %s\n", tokenString)

	// verify with TPM based publicKey
	keyFunc, err := tpmjwt.TPMVerfiyKeyfunc(ctx, config)
	if err != nil {
		log.Fatalf("could not get keyFunc: %v", err)
	}

	vtoken, err := jwt.Parse(tokenString, keyFunc)
	if err != nil {
		log.Fatalf("Error verifying token %v", err)
	}
	if vtoken.Valid {
		log.Println("     verified with Signer PublicKey")
	}

	// verify with provided RSAPublic key

	rc, err := os.ReadFile("../certs/akcert.pem")
	if err != nil {
		fmt.Println(err)
		return
	}

	block, _ := pem.Decode(rc)

	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		fmt.Println(err)
		return
	}

	pk := c.PublicKey

	v, err := jwt.Parse(vtoken.Raw, func(token *jwt.Token) (interface{}, error) {
		return pk, nil
	})
	if err != nil {
		log.Fatalf("Error verifying token %v", err)
	}
	if v.Valid {
		log.Println("     verified with exported PubicKey")
	}

}
