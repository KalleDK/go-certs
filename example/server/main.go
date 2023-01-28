package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"syscall"

	"github.com/KalleDK/go-certs"
)

func main() {
	mux := http.NewServeMux()

	certmanger := &certs.FileBackend{
		CertPath: "cert.pem",
		KeyPath:  "cert.key",
	}

	if err := certmanger.Reload(); err != nil {
		log.Fatal(err)
	}

	certs.Notify(certmanger, syscall.SIGHUP)

	tlsConf := &tls.Config{
		GetCertificate: certmanger.GetCertificate,
	}

	srv := &http.Server{
		Addr:      ":9090",
		Handler:   mux,
		TLSConfig: tlsConf,
	}

	mux.HandleFunc("/ping", func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprintf(w, "pong!")
		certs.Stop(certmanger)
	})

	srv.ListenAndServeTLS("", "")
}
