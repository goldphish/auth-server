package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"path/filepath"
)

var port = flag.Int("port", 8080, "Port to listen on")
var caPath = flag.String("ca_path", "/certs", "Path to certs")

type Fingerprint struct {
	Fingerprint_sha256 string `json:"fingerprint_sha256"`
}

type AuthUsers struct {
	Certificates []Fingerprint `json:"certificates"`
}

type CertServer struct {
	au AuthUsers
}

func (c *CertServer) loadAllCertFiles() error {
	files, err := ioutil.ReadDir(*caPath)
	if err != nil {
		return err
	}

	for _, file := range files {
		log.Printf("Reading %v", file.Name())
		fullPath := filepath.Join(*caPath, file.Name())
		err := c.loadCertFromFile(fullPath)
		if err != nil {
			return err
		}
	}
	return err
}

func (c *CertServer) loadCertFromFile(f string) error {
	data, err := ioutil.ReadFile(f)
	if err != nil {
		return err
	}
	for len(data) > 0 {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return err
		}
		fp256 := sha256.Sum256(cert.Raw)
		fp := Fingerprint{Fingerprint_sha256: hex.EncodeToString(fp256[:])}
		log.Printf("Read fingerprint: %v", fp)
		c.au.Certificates = append(c.au.Certificates, fp)
	}
	return nil
}

func (c *CertServer) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	log.Print(req)
	if len(c.au.Certificates) == 0 {
		err := c.loadAllCertFiles()
		if err != nil {
			log.Fatal(err)
		}
	}
	json.NewEncoder(w).Encode(c.au)
}

func main() {
	flag.Parse()
	http.Handle("/v1/certs/list/approved", new(CertServer))
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%v", *port), nil))
}
