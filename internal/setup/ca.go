// Installation CA («собственный CA установки»): creation, server certificate
// issuance and protected export. The CA private key is exported encrypted
// (scrypt + AES-256-GCM envelope, standard primitives), the working copy is
// deleted from the server only after a successful export and explicit
// administrator confirmation.
package setup

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/scrypt"
)

const (
	scryptN = 1 << 15
	scryptR = 8
	scryptP = 1
)

// CAKeyEnvelope is the format of the exported encrypted CA key.
const CAKeyEnvelopePEMType = "MANDATNIK ENCRYPTED PRIVATE KEY"

// CreateInstallationCA creates a new root CA for the installation.
func CreateInstallationCA(commonName string, validityDays int) (cert *x509.Certificate, key *rsa.PrivateKey, err error) {
	if validityDays < 365 || validityDays > 3650 {
		validityDays = 1825
	}
	key, err = rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return nil, nil, fmt.Errorf("генерирую ключ УЦ: %w", err)
	}
	serial, err := NewSerial()
	if err != nil {
		return nil, nil, err
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{"Mandatnik Installation CA"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(0, 0, validityDays),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		MaxPathLen:            1,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("создаю самоподписанный УЦ: %w", err)
	}
	cert, err = x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

// IssueServerCert issues a server certificate signed by the installation CA.
func IssueServerCert(ca *x509.Certificate, caKey any, commonName string, hosts []string, validityDays int) (cert *x509.Certificate, key *rsa.PrivateKey, err error) {
	if validityDays < 30 || validityDays > 825 {
		validityDays = 397
	}
	caRSA, ok := caKey.(*rsa.PrivateKey)
	if !ok {
		return nil, nil, errors.New("ключ УЦ имеет неподдерживаемый тип")
	}
	key, err = rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return nil, nil, fmt.Errorf("генерирую ключ сервера: %w", err)
	}
	serial, err := NewSerial()
	if err != nil {
		return nil, nil, err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName, Organization: []string{"Mandatnik"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(0, 0, validityDays),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	dnsNames, ipAddresses, err := splitHosts(hosts)
	if err != nil {
		return nil, nil, err
	}
	template.DNSNames = dnsNames
	template.IPAddresses = ipAddresses
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caRSA)
	if err != nil {
		return nil, nil, fmt.Errorf("выпускаю сертификат сервера: %w", err)
	}
	cert, err = x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

// splitHosts separates DNS names and IP addresses for SAN fields.
func splitHosts(hosts []string) ([]string, []net.IP, error) {
	var dns []string
	var ips []net.IP
	for _, host := range hosts {
		host = strings.TrimSuffix(strings.TrimSpace(host), ".")
		if host == "" {
			continue
		}
		if ip := net.ParseIP(host); ip != nil {
			ips = append(ips, ip)
		} else {
			dns = append(dns, strings.ToLower(host))
		}
	}
	if len(dns) == 0 && len(ips) == 0 {
		return nil, nil, errors.New("не указано ни одного адреса (DNS-имя или IP) для SAN")
	}
	return dns, ips, nil
}

// EncryptPEMKey wraps a PKCS#8 private key in the scrypt+AES-GCM envelope.
func EncryptPEMKey(key any, passphrase string) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("кодирую ключ: %w", err)
	}
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	derived, err := scrypt.Key([]byte(passphrase), salt, scryptN, scryptR, scryptP, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(derived)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	sealed := gcm.Seal(nil, nonce, der, salt)
	header := []byte{1, byte(scryptN >> 16 & 0xff), byte(scryptN >> 8 & 0xff), byte(scryptN & 0xff), byte(scryptR), byte(scryptP)}
	payload := append(append(header, salt...), append(nonce, sealed...)...)
	return pem.EncodeToMemory(&pem.Block{Type: CAKeyEnvelopePEMType, Bytes: payload}), nil
}

// DecryptPEMKey opens the exported CA key envelope.
func DecryptPEMKey(path, passphrase string) (any, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("читаю ключ УЦ %s: %w", path, err)
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != CAKeyEnvelopePEMType {
		return nil, fmt.Errorf("файл %s не является зашифрованным ключом УЦ формата %s", path, CAKeyEnvelopePEMType)
	}
	payload := block.Bytes
	if len(payload) < 6+16+16 {
		return nil, errors.New("файл ключа УЦ повреждён")
	}
	n := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	r, p := int(payload[4]), int(payload[5])
	payload = payload[6:]
	salt, rest := payload[:16], payload[16:]
	nonce, sealed := rest[:12], rest[12:]
	derived, err := scrypt.Key([]byte(passphrase), salt, n, r, p, 32)
	if err != nil {
		return nil, err
	}
	g, err := aes.NewCipher(derived)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(g)
	if err != nil {
		return nil, err
	}
	der, err := gcm.Open(nil, nonce, sealed, salt)
	if err != nil {
		return nil, errors.New("пароль ключа УЦ неверен или файл повреждён")
	}
	if len(der) == 0 {
		return nil, errors.New("пароль ключа УЦ неверен или файл повреждён")
	}
	key, parseErr := x509.ParsePKCS8PrivateKey(der)
	if parseErr != nil {
		return nil, errors.New("пароль ключа УЦ неверен или файл повреждён")
	}
	return key, nil
}

// WriteCAFiles exports the public CA certificate and the encrypted CA key.
func WriteCAFiles(certPath, keyPath string, cert *x509.Certificate, key any, passphrase string) error {
	if err := os.MkdirAll(filepath.Dir(certPath), 0o700); err != nil {
		return err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return fmt.Errorf("пишу публичный сертификат УЦ: %w", err)
	}
	enc, err := EncryptPEMKey(key, passphrase)
	if err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, enc, 0o600); err != nil {
		return fmt.Errorf("пишу зашифрованный ключ УЦ: %w", err)
	}
	return secureFile(keyPath)
}

// DeleteWorkingKey removes the working copy of the CA private key. Server
// private keys are never touched by this helper.
func DeleteWorkingKey(path string) error {
	err := os.Remove(path)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}
