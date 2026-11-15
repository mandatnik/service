// Certificate validation and issuance for the setup wizard. Validation is
// structural: SAN coverage, key match, expiry, key usage, EKU, algorithms,
// chain building. Trust on the server is checked when trust anchors are
// available; distributing trust to client machines is documented separately.
package setup

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// CertCheck is the result of validating one server certificate.
type CertCheck struct {
	Subject      string   `json:"subject"`
	Issuer       string   `json:"issuer"`
	SerialHex    string   `json:"serial"`
	NotBefore    string   `json:"not_before"`
	NotAfter     string   `json:"not_after"`
	SANs         []string `json:"sans"`
	KeyAlgorithm string   `json:"key_algorithm"`
	Signature    string   `json:"signature_algorithm"`
	Expired      bool     `json:"expired"`
	ExpiringSoon bool     `json:"expiring_soon"`
	OK           bool     `json:"ok"`
	Problems     []string `json:"problems,omitempty"`
	Warnings     []string `json:"warnings,omitempty"`
}

// TLS server EKU OID.
var oidServerAuth = x509.ExtKeyUsageServerAuth

// HostCovered reports whether the certificate covers the host as DNS SAN or
// IP SAN. CN is deliberately ignored: SAN is authoritative.
func HostCovered(cert *x509.Certificate, host string) bool {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "" {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		for _, san := range cert.IPAddresses {
			if ip.Equal(san) {
				return true
			}
		}
		return false
	}
	for _, san := range cert.DNSNames {
		if matchDNS(host, strings.ToLower(san)) {
			return true
		}
	}
	return false
}

func matchDNS(host, pattern string) bool {
	if pattern == "" {
		return false
	}
	if pattern == host {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // ".example.com"
		if strings.HasSuffix(host, suffix) && !strings.Contains(strings.TrimSuffix(host, suffix), ".") {
			return true
		}
	}
	return false
}

// ValidateServerCert performs the structural and trust checks required before
// the wizard accepts a certificate for TLS listeners. trustAnchors may be nil,
// in which case trust is reported as unverified rather than assumed.
func ValidateServerCert(leaf *x509.Certificate, chain []*x509.Certificate, hosts []string, trustAnchors []*x509.Certificate, now time.Time) (*CertCheck, error) {
	if leaf == nil {
		return nil, errors.New("сертификат не передан")
	}
	check := &CertCheck{
		Subject:      leaf.Subject.String(),
		Issuer:       leaf.Issuer.String(),
		SerialHex:    fmt.Sprintf("%x", leaf.SerialNumber),
		NotBefore:    leaf.NotBefore.Format(time.RFC3339),
		NotAfter:     leaf.NotAfter.Format(time.RFC3339),
		KeyAlgorithm: keyAlgorithm(leaf),
		Signature:    leaf.SignatureAlgorithm.String(),
	}
	for _, san := range leaf.DNSNames {
		check.SANs = append(check.SANs, san)
	}
	for _, ip := range leaf.IPAddresses {
		check.SANs = append(check.SANs, ip.String())
	}

	// Expiry.
	if now.Before(leaf.NotBefore) {
		check.Problems = append(check.Problems, fmt.Sprintf("сертификат ещё не действует (начало %s)", check.NotBefore))
	}
	if now.After(leaf.NotAfter) {
		check.Expired = true
		check.Problems = append(check.Problems, fmt.Sprintf("сертификат истёк %s", check.NotAfter))
	} else if leaf.NotAfter.Before(now.Add(30 * 24 * time.Hour)) {
		check.ExpiringSoon = true
		check.Warnings = append(check.Warnings, fmt.Sprintf("сертификат истекает меньше чем через 30 дней (%s)", check.NotAfter))
	}

	// SAN coverage for every address clients will use.
	for _, host := range hosts {
		if !HostCovered(leaf, host) {
			check.Problems = append(check.Problems, fmt.Sprintf("адрес %q отсутствует в SAN сертификата (CN вместо SAN не принимается)", host))
		}
	}

	// Key usage and EKU for a TLS server.
	if leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		check.Problems = append(check.Problems, "KeyUsage не содержит digitalSignature, требуемого для TLS-сервера")
	}
	if leaf.PublicKeyAlgorithm == x509.RSA && leaf.KeyUsage&x509.KeyUsageKeyEncipherment == 0 {
		check.Problems = append(check.Problems, "KeyUsage не содержит keyEncipherment (необходим RSA-обмен ключами TLS)")
	}
	hasServerAuth := false
	for _, eku := range leaf.ExtKeyUsage {
		if eku == oidServerAuth {
			hasServerAuth = true
			break
		}
	}
	if !hasServerAuth {
		check.Problems = append(check.Problems, "ExtendedKeyUsage не содержит Server Authentication")
	}

	// Algorithm support of the Go TLS stack used by the backend.
	switch {
	case leaf.PublicKeyAlgorithm == x509.RSA:
		size, _ := leaf.PublicKey.(*rsa.PublicKey)
		if size.N.BitLen() < 2048 {
			check.Problems = append(check.Problems, fmt.Sprintf("RSA-ключ слишком короткий (%d бит, минимум 2048)", size.N.BitLen()))
		}
	case leaf.PublicKeyAlgorithm == x509.ECDSA:
		key := leaf.PublicKey.(*ecdsa.PublicKey)
		if key.Curve == elliptic.P224() {
			check.Problems = append(check.Problems, "кривая P-224 не поддерживается TLS-стеком")
		}
	case leaf.PublicKeyAlgorithm == x509.Ed25519:
		// supported
	default:
		check.Problems = append(check.Problems, "алгоритм открытого ключа не поддерживается TLS-стеком")
	}
	if leaf.SignatureAlgorithm == x509.MD5WithRSA || leaf.SignatureAlgorithm == x509.SHA1WithRSA || leaf.SignatureAlgorithm == x509.DSAWithSHA1 || leaf.SignatureAlgorithm == x509.ECDSAWithSHA1 {
		check.Problems = append(check.Problems, "алгоритм подписи (MD5/SHA-1) не поддерживается TLS 1.2+")
	}

	// Key/certificate pairing was verified by the loader; chain trust here.
	check.OK = len(check.Problems) == 0
	if err := buildChain(leaf, chain, trustAnchors, check); err != nil {
		return check, err
	}
	return check, nil
}

func buildChain(leaf *x509.Certificate, provided []*x509.Certificate, anchors []*x509.Certificate, check *CertCheck) error {
	roots := x509.NewCertPool()
	inter := x509.NewCertPool()
	knownRoots := false
	for _, cert := range anchors {
		roots.AddCert(cert)
		knownRoots = true
	}
	for _, cert := range provided {
		inter.AddCert(cert)
	}
	opts := x509.VerifyOptions{
		CurrentTime:   time.Now(),
		Intermediates: inter,
	}
	if knownRoots {
		opts.Roots = roots
	}
	if _, err := leaf.Verify(opts); err != nil {
		if !knownRoots {
			check.Warnings = append(check.Warnings,
				"структура сертификата корректна, но доверие к УЦ на этом сервере проверить не удалось (корневые сертификаты не переданы); доверие потребуется распространить на клиентские машины")
			return nil
		}
		check.Problems = append(check.Problems, fmt.Sprintf("цепочка сертификата не проверяется: %v", err))
		check.OK = false
	} else if knownRoots {
		check.Warnings = append(check.Warnings,
			"цепочка доверена на этом сервере; корневой сертификат УЦ всё равно нужно распространить на клиентские машины (АРМ, интеграции)")
	}
	return nil
}

// LoadPEM reads a PEM certificate (leaf first, extra certificates become the
// chain) and optionally a separate key file.
func LoadPEM(certPath, keyPath string) (*x509.Certificate, []*x509.Certificate, any, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("читаю сертификат %s: %w", certPath, err)
	}
	var certs []*x509.Certificate
	rest := certPEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" && !strings.HasSuffix(block.Type, "CERTIFICATE") {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("сертификат %s: некорректный формат: %w", certPath, err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, nil, nil, fmt.Errorf("файл %s не содержит PEM-сертификатов", certPath)
	}
	var key any
	if keyPath != "" {
		key, err = loadPrivateKey(keyPath)
		if err != nil {
			return nil, nil, nil, err
		}
		if err := keysMatch(certs[0], key); err != nil {
			return nil, nil, nil, err
		}
	}
	return certs[0], certs[1:], key, nil
}

// LoadPFX reads a PKCS#12/PFX bundle; the password is provided by the
// administrator through the hidden prompt, never via a command-line argument.
func LoadPFX(path, password string) (*x509.Certificate, []*x509.Certificate, any, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("читаю PFX %s: %w", path, err)
	}
	key, leaf, chain, err := pkcs12.DecodeChain(raw, password)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("PFX %s: %w (проверьте пароль и формат PKCS#12)", path, err)
	}
	if key == nil {
		return nil, nil, nil, fmt.Errorf("PFX %s не содержит закрытого ключа", path)
	}
	if err := keysMatch(leaf, key); err != nil {
		return nil, nil, nil, err
	}
	return leaf, chain, key, nil
}

func loadPrivateKey(path string) (any, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("читаю закрытый ключ %s: %w", path, err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		if key, err := x509.ParsePKCS8PrivateKey(raw); err == nil {
			return key, nil
		}
		if key, err := x509.ParsePKCS1PrivateKey(raw); err == nil {
			return key, nil
		}
		if key, err := x509.ParseECPrivateKey(raw); err == nil {
			return key, nil
		}
		return nil, fmt.Errorf("файл %s не содержит PEM/DER закрытого ключа", path)
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY", "ENCRYPTED PRIVATE KEY":
		if x509.IsEncryptedPEMBlock(block) { //nolint:staticcheck // legacy format support
			return nil, errors.New("зашифрованный PEM-ключ устаревшего формата не поддерживается; используйте PFX/PKCS#8 без шифрования PEM или PFX")
		}
		return x509.ParsePKCS8PrivateKey(block.Bytes)
	case "MANDATNIK ENCRYPTED PRIVATE KEY":
		return nil, errors.New("ключ собственного УЦ установки сначала расшифруйте командой восстановления (экспортированный ключ CA)")
	default:
		return nil, fmt.Errorf("файл %s содержит блок PEM %q, а не закрытый ключ", path, block.Type)
	}
}

// keysMatch verifies that the private key corresponds to the certificate.
func keysMatch(cert *x509.Certificate, key any) error {
	pub := cert.PublicKey
	switch k := key.(type) {
	case *rsa.PrivateKey:
		if pubRSA, ok := pub.(*rsa.PublicKey); !ok || pubRSA.N.Cmp(k.N) != 0 {
			return errors.New("закрытый ключ не соответствует сертификату")
		}
	case *ecdsa.PrivateKey:
		if pubEC, ok := pub.(*ecdsa.PublicKey); !ok || pubEC.X.Cmp(k.X) != 0 || pubEC.Y.Cmp(k.Y) != 0 {
			return errors.New("закрытый ключ не соответствует сертификату")
		}
	case ed25519.PrivateKey:
		if pubEd, ok := pub.(ed25519.PublicKey); !ok || !pubEd.Equal(ed25519.PublicKey(k[32:])) {
			return errors.New("закрытый ключ не соответствует сертификату")
		}
	default:
		return errors.New("неподдерживаемый тип закрытого ключа")
	}
	return nil
}

// KeyMatchesTLS confirms a parsed key can be used in tls.Certificate.
func KeyMatchesTLS(cert *x509.Certificate, key any) error {
	if err := keysMatch(cert, key); err != nil {
		return err
	}
	_, err := tls.X509KeyPair(marshalCert(cert), marshalKey(key))
	return err
}

func marshalCert(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

func marshalKey(key any) []byte {
	if rsaKey, ok := key.(*rsa.PrivateKey); ok {
		return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)})
	}
	if ecKey, ok := key.(*ecdsa.PrivateKey); ok {
		der, _ := x509.MarshalECPrivateKey(ecKey)
		return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	}
	if edKey, ok := key.(ed25519.PrivateKey); ok {
		der, _ := x509.MarshalPKCS8PrivateKey(edKey)
		return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	}
	return nil
}

func keyAlgorithm(cert *x509.Certificate) string {
	switch key := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA-%d", key.N.BitLen())
	case *ecdsa.PublicKey:
		return "ECDSA " + key.Curve.Params().Name
	case ed25519.PublicKey:
		return "Ed25519"
	default:
		return cert.PublicKeyAlgorithm.String()
	}
}

// CreateKeyAndCSR generates an RSA-3072 key, saves it protected and returns a
// CSR covering the requested hosts (DNS and IP SANs).
func CreateKeyAndCSR(keyPath, csrPath, commonName string, hosts []string) ([]byte, error) {
	key, err := rsa.GenerateKey(randReader(), 3072)
	if err != nil {
		return nil, fmt.Errorf("генерирую закрытый ключ: %w", err)
	}
	csr, err := newCSR(key, commonName, hosts)
	if err != nil {
		return nil, err
	}
	if err := writeKeyFile(keyPath, marshalKey(key)); err != nil {
		return nil, err
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr.Raw})
	if err := os.WriteFile(csrPath, csrPEM, 0o600); err != nil {
		return nil, fmt.Errorf("пишу CSR: %w", err)
	}
	if err := secureFile(csrPath); err != nil {
		return nil, err
	}
	return csrPEM, nil
}

func newCSR(key *rsa.PrivateKey, commonName string, hosts []string) (*x509.CertificateRequest, error) {
	if commonName == "" {
		commonName = firstHost(hosts)
	}
	template := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: commonName, Organization: []string{"Mandatnik"}},
	}
	if err := addSANs(template, hosts); err != nil {
		return nil, err
	}
	der, err := x509.CreateCertificateRequest(randReader(), template, key)
	if err != nil {
		return nil, fmt.Errorf("создаю CSR: %w", err)
	}
	return x509.ParseCertificateRequest(der)
}

func addSANs(template *x509.CertificateRequest, hosts []string) error {
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
		return errors.New("не указано ни одного адреса (DNS-имя или IP) для SAN")
	}
	template.DNSNames = dns
	template.IPAddresses = ips
	return nil
}

func firstHost(hosts []string) string {
	if len(hosts) == 0 {
		return "Mandatnik Backend"
	}
	return hosts[0]
}

func writeKeyFile(path string, pemBytes []byte) error {
	if err := os.MkdirAll(dirOf(path), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		return fmt.Errorf("пишу закрытый ключ %s: %w", path, err)
	}
	return secureFile(path)
}

// CertFileSummary describes a certificate file for wizard display.
func CertFileSummary(path string) (*CertCheck, error) {
	leaf, _, _, err := LoadPEM(path, "")
	if err != nil {
		return nil, err
	}
	check, err := ValidateServerCert(leaf, nil, nil, nil, time.Now())
	if err != nil {
		return nil, err
	}
	return check, nil
}

// KeyFingerprint returns a stable public-key fingerprint for audit lines.
func KeyFingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return fmt.Sprintf("sha256:%x", sum)
}

// NewSerial returns a random positive serial number.
func NewSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := randInt(limit)
	if err != nil {
		return nil, err
	}
	return serial.Add(serial, big.NewInt(1)), nil
}
