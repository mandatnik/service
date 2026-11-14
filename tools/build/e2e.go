package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

// Run the candidate backend, not the currently deployed server. Only loopback
// ports and a short-lived test CA are used. The authorized SQL stand is real.
func endToEnd(o options) (err error) {
	tmp, err := os.MkdirTemp("", "telehack-e2e-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	raw, err := os.ReadFile(o.config)
	if err != nil {
		return err
	}
	var acceptance map[string]json.RawMessage
	if err = json.Unmarshal(raw, &acceptance); err != nil {
		return err
	}
	certPath, keyPath, cert, err := ephemeralTLS(tmp)
	if err != nil {
		return err
	}
	agent, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	admin, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		agent.Close()
		return err
	}
	integration, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		agent.Close()
		admin.Close()
		return err
	}
	agentAddress, adminAddress := agent.Addr().String(), admin.Addr().String()
	integrationAddress := integration.Addr().String()
	agent.Close()
	admin.Close()
	integration.Close()
	config := map[string]any{"agent_listen": agentAddress, "admin_listen": adminAddress, "integration_listen": integrationAddress, "tls_cert_file": certPath, "tls_key_file": keyPath, "log_file": filepath.Join(tmp, "backend.txt"), "db": acceptance["db"]}
	backendConfig := filepath.Join(tmp, "backend.json")
	data, _ := json.Marshal(config)
	if err = os.WriteFile(backendConfig, data, 0600); err != nil {
		return err
	}
	acceptance["server_url"], _ = json.Marshal("https://" + agentAddress)
	acceptance["ca_file"], _ = json.Marshal(certPath)
	acceptanceConfig := filepath.Join(tmp, "acceptance.json")
	data, _ = json.Marshal(acceptance)
	if err = os.WriteFile(acceptanceConfig, data, 0600); err != nil {
		return err
	}
	binary := filepath.Join(tmp, "backend")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	if err = run(map[string]string{"CGO_ENABLED": "0", "GOOS": runtime.GOOS, "GOARCH": runtime.GOARCH}, "go", "build", "-trimpath", "-o", binary, "./cmd/backend"); err != nil {
		return err
	}
	log, err := os.Create(filepath.Join(tmp, "process.log"))
	if err != nil {
		return err
	}
	defer log.Close()
	child := exec.Command(binary, "run", "-config", backendConfig)
	child.Stdout = log
	child.Stderr = log
	if err = child.Start(); err != nil {
		return err
	}
	stopped := make(chan struct{})
	var exitError error
	go func() { exitError = child.Wait(); close(stopped) }()
	defer func() {
		_ = child.Process.Kill()
		<-stopped
		if err != nil {
			data, e := os.ReadFile(filepath.Join(tmp, "backend.txt"))
			if e != nil {
				data, e = os.ReadFile(filepath.Join(tmp, "process.log"))
			}
			if e == nil {
				_ = os.MkdirAll(o.evidence, 0755)
				_ = os.WriteFile(filepath.Join(o.evidence, "candidate-backend.txt"), data, 0600)
			}
		}
	}()
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	client := http.Client{Timeout: time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}}
	deadline := time.Now().Add(30 * time.Second)
	ready := false
	for time.Now().Before(deadline) {
		select {
		case <-stopped:
			return fmt.Errorf("candidate backend exited before readiness: %v (see evidence logs)", exitError)
		default:
		}
		response, e := client.Get("https://" + adminAddress + "/healthz")
		if e == nil {
			response.Body.Close()
			if response.StatusCode == 200 {
				ready = true
				break
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	if !ready {
		return fmt.Errorf("candidate backend did not become healthy; see %s/candidate-backend.txt", o.evidence)
	}
	fmt.Println("Candidate backend healthy on loopback; running signed HTTPS acceptance against real SQL Server")
	return run(nil, "go", "run", "./cmd/acceptance", "contract", "-config", acceptanceConfig, "-evidence", absolute(o.evidence))
}
func ephemeralTLS(dir string) (string, string, *x509.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", "", nil, err
	}
	template := x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "Telehack ephemeral CI TLS"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return "", "", nil, err
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", "", nil, err
	}
	certPath, keyPath := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	if err = os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		return "", "", nil, err
	}
	if err = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}), 0600); err != nil {
		return "", "", nil, err
	}
	cert, err := x509.ParseCertificate(der)
	return certPath, keyPath, cert, err
}
