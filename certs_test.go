package certs

import (
	"crypto/tls"
	_ "embed"
	"errors"
	"os"
	"os/signal"
	"reflect"
	"syscall"
	"testing"
	"testing/fstest"
	"time"
)

//go:embed testdata/cert1.pem
var cert1 []byte

//go:embed testdata/cert2.pem
var cert2 []byte

//go:embed testdata/key1.pem
var key1 []byte

//go:embed testdata/key2.pem
var key2 []byte

var fakeFS = fstest.MapFS{
	"cert1.pem": &fstest.MapFile{Data: cert1},
	"cert2.pem": &fstest.MapFile{Data: cert2},
	"key1.pem":  &fstest.MapFile{Data: key1},
	"key2.pem":  &fstest.MapFile{Data: key2},
}

func init() {
	FS = fakeFS
}

type DummyStore struct {
	ReloadCalled bool
	FailOnReload bool
	Signal       bool
	SignalChan   chan<- os.Signal
}

func (ms *DummyStore) Reload() (err error) {
	ms.ReloadCalled = true
	if ms.Signal {
		ms.Signal = false
		close(ms.SignalChan)
	}
	if ms.FailOnReload {
		return errors.New("failed reload")
	}
	return nil
}

func (ms *DummyStore) GetCertificateNoDefault(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return nil, nil
}

func (ms *DummyStore) GetCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return nil, nil
}

func TestMultiStore_Reload(t *testing.T) {
	type fields struct {
		Stores []*DummyStore
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "Reload",
			fields: fields{
				Stores: []*DummyStore{
					{},
					{},
				},
			},
			wantErr: false,
		},
		{
			name: "ReloadWithErrors",
			fields: fields{
				Stores: []*DummyStore{
					{},
					{FailOnReload: true},
					{},
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ms := &MultiStore{}
			for _, store := range tt.fields.Stores {
				ms.Stores = append(ms.Stores, store)
			}
			if err := ms.Reload(); (err != nil) != tt.wantErr {
				t.Errorf("MultiStore.Reload() error = %v, wantErr %v", err, tt.wantErr)
			}
			for _, store := range tt.fields.Stores {
				if !store.ReloadCalled {
					t.Errorf("MultiStore.Reload() did not reload all stores")
				}
			}
		})
	}
}

func TestNewFileStore(t *testing.T) {
	type args struct {
		certPath string
		keyPath  string
	}
	tests := []struct {
		name    string
		args    args
		wantCr  [][]byte
		wantErr bool
	}{
		{
			name: "Default",
			args: args{
				certPath: "cert1.pem",
				keyPath:  "key1.pem",
			},
			wantCr:  [][]byte{{48, 130, 3, 71, 48, 130, 2, 47, 2, 20, 93, 212, 77, 4, 84, 142, 60, 20, 183, 5, 191, 234, 69, 200, 22, 116, 147, 49, 56, 92, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 11, 5, 0, 48, 95, 49, 11, 48, 9, 6, 3, 85, 4, 6, 19, 2, 68, 75, 49, 16, 48, 14, 6, 3, 85, 4, 8, 12, 7, 68, 101, 110, 109, 97, 114, 107, 49, 18, 48, 16, 6, 3, 85, 4, 7, 12, 9, 83, 105, 108, 107, 101, 98, 111, 114, 103, 49, 20, 48, 18, 6, 3, 85, 4, 10, 12, 11, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 49, 20, 48, 18, 6, 3, 85, 4, 3, 12, 11, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 48, 32, 23, 13, 50, 51, 48, 49, 50, 57, 48, 57, 52, 53, 50, 57, 90, 24, 15, 50, 50, 57, 54, 49, 49, 49, 51, 48, 57, 52, 53, 50, 57, 90, 48, 95, 49, 11, 48, 9, 6, 3, 85, 4, 6, 19, 2, 68, 75, 49, 16, 48, 14, 6, 3, 85, 4, 8, 12, 7, 68, 101, 110, 109, 97, 114, 107, 49, 18, 48, 16, 6, 3, 85, 4, 7, 12, 9, 83, 105, 108, 107, 101, 98, 111, 114, 103, 49, 20, 48, 18, 6, 3, 85, 4, 10, 12, 11, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 49, 20, 48, 18, 6, 3, 85, 4, 3, 12, 11, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 48, 130, 1, 34, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0, 3, 130, 1, 15, 0, 48, 130, 1, 10, 2, 130, 1, 1, 0, 183, 58, 27, 69, 112, 59, 4, 175, 204, 90, 177, 228, 10, 152, 72, 170, 77, 66, 232, 146, 115, 245, 73, 208, 69, 106, 137, 240, 88, 203, 21, 128, 37, 27, 196, 115, 237, 125, 28, 44, 44, 89, 90, 65, 24, 171, 137, 52, 106, 237, 197, 209, 229, 78, 46, 26, 137, 73, 102, 202, 68, 174, 84, 125, 123, 170, 108, 33, 23, 145, 13, 194, 215, 179, 200, 141, 144, 133, 108, 213, 176, 47, 184, 116, 8, 115, 94, 54, 20, 182, 140, 49, 165, 62, 245, 126, 154, 11, 138, 102, 93, 26, 227, 98, 126, 90, 12, 16, 171, 241, 161, 19, 43, 78, 190, 163, 222, 245, 171, 79, 66, 245, 193, 47, 232, 236, 67, 212, 179, 145, 25, 70, 23, 160, 250, 216, 67, 209, 174, 248, 23, 156, 64, 84, 57, 195, 177, 76, 251, 19, 80, 196, 51, 19, 36, 165, 217, 30, 216, 107, 250, 182, 44, 159, 1, 173, 236, 199, 78, 77, 126, 204, 142, 88, 216, 87, 101, 241, 249, 101, 40, 46, 34, 34, 117, 156, 211, 90, 206, 205, 150, 3, 15, 107, 74, 57, 153, 206, 228, 62, 91, 129, 60, 25, 217, 17, 159, 234, 239, 124, 144, 167, 168, 240, 136, 248, 69, 132, 73, 128, 142, 47, 1, 108, 97, 127, 157, 115, 66, 128, 200, 33, 170, 244, 32, 254, 190, 219, 75, 43, 30, 239, 174, 80, 114, 16, 47, 158, 63, 230, 94, 50, 70, 237, 161, 53, 2, 3, 1, 0, 1, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 11, 5, 0, 3, 130, 1, 1, 0, 168, 42, 4, 172, 54, 154, 77, 29, 93, 163, 79, 21, 211, 50, 168, 5, 68, 79, 98, 14, 220, 34, 165, 75, 72, 186, 170, 241, 83, 97, 200, 193, 33, 2, 111, 19, 27, 163, 145, 225, 66, 187, 232, 246, 211, 250, 56, 214, 198, 50, 172, 254, 203, 184, 169, 95, 138, 212, 37, 63, 87, 80, 208, 169, 35, 68, 255, 217, 70, 0, 187, 110, 68, 62, 217, 20, 26, 56, 208, 130, 169, 135, 104, 49, 190, 168, 144, 92, 125, 19, 121, 4, 52, 244, 26, 139, 58, 34, 150, 47, 154, 80, 104, 185, 86, 110, 187, 219, 170, 147, 207, 242, 153, 22, 71, 52, 108, 3, 202, 96, 227, 109, 85, 62, 55, 135, 29, 162, 183, 106, 144, 138, 69, 14, 199, 218, 11, 156, 136, 95, 125, 143, 103, 253, 127, 196, 111, 129, 176, 186, 119, 229, 155, 216, 125, 123, 38, 201, 172, 134, 164, 116, 75, 117, 22, 251, 111, 131, 243, 105, 26, 24, 144, 72, 231, 134, 16, 6, 203, 180, 228, 237, 52, 205, 205, 42, 174, 147, 193, 137, 10, 230, 237, 59, 215, 189, 220, 78, 141, 251, 201, 155, 119, 47, 237, 221, 128, 188, 50, 251, 107, 87, 184, 111, 168, 138, 63, 28, 222, 26, 73, 78, 142, 252, 236, 42, 20, 211, 117, 229, 196, 142, 161, 213, 81, 48, 187, 75, 103, 156, 35, 135, 241, 197, 188, 74, 198, 45, 123, 99, 50, 183, 5, 15, 212, 213}},
			wantErr: false,
		},
		{
			name: "MissingCert",
			args: args{
				certPath: "cert3.pem",
				keyPath:  "key1.pem",
			},
			wantErr: true,
		},
		{
			name: "MissingKey",
			args: args{
				certPath: "cert1.pem",
				keyPath:  "key3.pem",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotCr, err := NewFileStore(tt.args.certPath, tt.args.keyPath)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewFileStore() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}
			if !reflect.DeepEqual(gotCr.Cert.Certificate, tt.wantCr) {
				t.Errorf("NewFileStore() = %v, want %v", gotCr.Cert.Certificate, tt.wantCr)
			}
		})
	}
}

func TestNotify(t *testing.T) {
	type args struct {
		r *DummyStore
		s syscall.Signal
		c chan os.Signal
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "Reload",
			args: args{
				r: &DummyStore{
					Signal: true,
				},
				s: syscall.SIGHUP,
				c: make(chan os.Signal),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.args.r.SignalChan = tt.args.c
			Notify(tt.args.r, tt.args.s)
			syscall.Kill(syscall.Getpid(), tt.args.s)
			waitSig(t, tt.args.c)
		})
	}
}

func TestNotifyTwice(t *testing.T) {
	type args struct {
		r *DummyStore
		s syscall.Signal
		c chan os.Signal
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "Reload",
			args: args{
				r: &DummyStore{
					Signal: true,
				},
				s: syscall.SIGHUP,
				c: make(chan os.Signal),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.args.r.SignalChan = tt.args.c
			Notify(tt.args.r, tt.args.s)
			Notify(tt.args.r, tt.args.s)
			syscall.Kill(syscall.Getpid(), tt.args.s)
			waitSig(t, tt.args.c)
		})
	}
}

func TestNotifyTwiceRemove(t *testing.T) {
	type args struct {
		r *DummyStore
		s syscall.Signal
		c chan os.Signal
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "Reload",
			args: args{
				r: &DummyStore{
					Signal: true,
				},
				s: syscall.SIGHUP,
				c: make(chan os.Signal),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.args.r.SignalChan = tt.args.c
			Notify(tt.args.r, tt.args.s)
			Notify(tt.args.r, tt.args.s)
			Stop(tt.args.r)
			c := make(chan os.Signal, 1)
			signal.Notify(c, syscall.SIGHUP)
			syscall.Kill(syscall.Getpid(), tt.args.s)
			waitSig(t, c)
		})
	}
}

func TestNotifyTwiceRemoveTwice(t *testing.T) {
	type args struct {
		r *DummyStore
		s syscall.Signal
		c chan os.Signal
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "Reload",
			args: args{
				r: &DummyStore{
					Signal: true,
				},
				s: syscall.SIGHUP,
				c: make(chan os.Signal),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.args.r.SignalChan = tt.args.c
			Notify(tt.args.r, tt.args.s)
			Notify(tt.args.r, tt.args.s)
			Stop(tt.args.r)
			Stop(tt.args.r)
			c := make(chan os.Signal, 1)
			signal.Notify(c, syscall.SIGHUP)
			syscall.Kill(syscall.Getpid(), tt.args.s)
			waitSig(t, c)
		})
	}
}

var settleTime = 100 * time.Millisecond
var fatalWaitingTime = 30 * time.Second

func waitSig(t *testing.T, c <-chan os.Signal) {
	t.Helper()

	// Sleep multiple times to give the kernel more tries to
	// deliver the signal.
	start := time.Now()
	timer := time.NewTimer(settleTime / 10)
	defer timer.Stop()

	for time.Since(start) < fatalWaitingTime {
		select {
		case <-c:
			return
		case <-timer.C:
			timer.Reset(settleTime / 10)
		}
	}
	t.Fatalf("timeout after %v waiting", fatalWaitingTime)
}
