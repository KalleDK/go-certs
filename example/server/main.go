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

type DummySwitcher struct {
	PrimCert string
	PrimKey  string
	SecCert  string
	SecKey   string
	Store    certs.FileStore
}

func (ds *DummySwitcher) Switch() {
	ds.PrimCert, ds.SecCert = ds.SecCert, ds.PrimCert
	ds.PrimKey, ds.SecKey = ds.SecKey, ds.PrimKey
	ds.Store.CertPath = ds.PrimCert
	ds.Store.KeyPath = ds.PrimKey
}

func serv() {

	// You can see the difference in the certs by the end date
	// *  expire date: Nov 13 09:45:29 2296 GMT
	// *  expire date: Aug 29 09:49:43 2570 GMT
	ds := DummySwitcher{
		PrimCert: "cert1.pem",
		PrimKey:  "key1.pem",
		SecCert:  "cert2.pem",
		SecKey:   "key2.pem",
	}
	ds.Switch()

	mux := http.NewServeMux()

	certmanger := &ds.Store

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
	})

	mux.HandleFunc("/disable", func(w http.ResponseWriter, req *http.Request) {
		certs.Stop(certmanger)
		fmt.Fprintf(w, "pong!")
	})

	mux.HandleFunc("/enable", func(w http.ResponseWriter, req *http.Request) {
		certs.Stop(certmanger)
		fmt.Fprintf(w, "pong!")
	})

	mux.HandleFunc("/switch", func(w http.ResponseWriter, req *http.Request) {
		ds.Switch()
		fmt.Fprintf(w, "pong!")
	})

	mux.HandleFunc("/switchreload", func(w http.ResponseWriter, req *http.Request) {
		ds.Switch()
		certmanger.Reload()
		fmt.Fprintf(w, "pong!")
	})

	srv.ListenAndServeTLS("", "")
}

func main() {

	serv()
}
