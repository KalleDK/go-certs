package certs

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
)

type Reloader interface {
	Reload() error
}

type Store interface {
	Reloader
	GetCertificateNoDefault(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error)
	GetCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error)
}

// #region Multistore

type MultiStore struct {
	Stores []Store
}

func (ms *MultiStore) Reload() (err error) {
	for _, store := range ms.Stores {
		if s_err := store.Reload(); s_err != nil {
			if err == nil {
				err = errors.New("error while reloading multiple stores")
			}
			err = fmt.Errorf("%w; %w", err, s_err)
		}
	}
	return err
}

func (ms *MultiStore) GetCertificateNoDefault(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	for _, store := range ms.Stores {
		cert, err := store.GetCertificateNoDefault(clientHello)
		if err != nil {
			return nil, err
		}
		if cert != nil {
			return cert, nil
		}
	}
	return nil, nil
}

func (ms *MultiStore) GetCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	for _, store := range ms.Stores {
		cert, err := store.GetCertificateNoDefault(clientHello)
		if err != nil {
			return nil, err
		}
		if cert != nil {
			return cert, nil
		}
	}
	if len(ms.Stores) < 1 {
		return nil, errors.New("no cert stores")
	}
	return ms.Stores[0].GetCertificate(clientHello)
}

// #endregion

// #region Filestore

type FileStore struct {
	CertPath string
	KeyPath  string
	Cert     tls.Certificate
}

func NewFileStore(certPath, keyPath string) (cr *FileStore, err error) {
	cr = &FileStore{
		CertPath: certPath,
		KeyPath:  keyPath,
	}

	if err := cr.Reload(); err != nil {
		return nil, err
	}

	return cr, nil
}

func (cr *FileStore) Reload() (err error) {
	cert, err := tls.LoadX509KeyPair(cr.CertPath, cr.KeyPath)
	if err != nil {
		return err
	}

	cr.Cert = cert

	return nil
}

func (cr *FileStore) GetCertificateNoDefault(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if clientHello.SupportsCertificate(&cr.Cert) != nil {
		return &cr.Cert, nil
	}
	return nil, nil
}

func (cr *FileStore) GetCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return &cr.Cert, nil
}

// #endregion

// #region Signal Reloader

var mux = sync.Mutex{}
var managers = map[Reloader]chan os.Signal{}

func reloadFromSignal(r Reloader, c <-chan os.Signal) {
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
}

func Notify(r Reloader, s os.Signal) {
	mux.Lock()
	defer mux.Unlock()

	if _, ok := managers[r]; ok {
		return
	}

	c := make(chan os.Signal, 1)

	go reloadFromSignal(r, c)

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

// #endregion
