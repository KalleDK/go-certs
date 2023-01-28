package certs

import (
	"crypto/tls"
	"log"
	"os"
	"os/signal"
	"sync"
)

type Manager struct {
	Cert tls.Certificate
}

func (cr *Manager) GetCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return &cr.Cert, nil
}

type FileBackend struct {
	Manager
	CertPath string
	KeyPath  string
}

func NewFromFile(certPath, keyPath string) (cr *FileBackend, err error) {
	cr = &FileBackend{
		CertPath: certPath,
		KeyPath:  keyPath,
	}

	if err := cr.Reload(); err != nil {
		return nil, err
	}

	return cr, nil
}

func (cr *FileBackend) Reload() (err error) {
	cert, err := tls.LoadX509KeyPair(cr.CertPath, cr.KeyPath)
	if err != nil {
		return err
	}

	cr.Cert = cert

	return nil
}

type Reloader interface {
	Reload() error
}

var mux = sync.Mutex{}
var managers = map[Reloader]chan os.Signal{}

func Notify(r Reloader, s os.Signal) {
	mux.Lock()
	defer mux.Unlock()

	if _, ok := managers[r]; ok {
		return
	}

	c := make(chan os.Signal, 1)

	go func(r Reloader, c chan os.Signal) {
		log.Printf("Starting receiving signals")
		for {
			if _, more := <-c; !more {
				log.Printf("Stopping receiving signals")
				return
			}
			log.Printf("Received SIGHUP, reloading")
			if err := r.Reload(); err != nil {
				log.Printf("Keeping old TLS certificate because the new one could not be loaded: %v", err)
			}
		}
	}(r, c)

	signal.Notify(c, s)
	managers[r] = c

}

func Stop(r Reloader) {
	mux.Lock()
	defer mux.Unlock()

	c, ok := managers[r]
	if !ok {
		return
	}

	signal.Stop(c)
	close(c)
	delete(managers, r)
}
