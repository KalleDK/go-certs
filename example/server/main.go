package main

import (
	"crypto/tls"
	_ "embed"
	"fmt"
	"log"
	"net/http"
	"syscall"

	"github.com/KalleDK/go-certs"
)

func serv() {
	mux := http.NewServeMux()

	certmanger := certs.MultiStore{
		Stores: []certs.Store{
			&certs.FileStore{
				CertPath: "cert1.pem",
				KeyPath:  "cert1.key",
			},
			&certs.FileStore{
				CertPath: "cert2.pem",
				KeyPath:  "cert2.key",
			},
		},
	}

	if err := certmanger.Reload(); err != nil {
		log.Fatal(err)
	}

	certs.Notify(&certmanger, syscall.SIGHUP)

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
		certs.Stop(&certmanger)
	})

	srv.ListenAndServeTLS("", "")
}

func main() {

	serv()
}
