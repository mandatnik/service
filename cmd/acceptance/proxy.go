package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"sync/atomic"
	"time"

	"telehack2026/internal/protocol"
)

// runP10Proxy is a deterministic acceptance-only fault injector. It terminates
// TLS with the backend certificate, forwards normal traffic, and discards the
// first successful /report response after the request reached SQL. The agent
// must retry the same report_id and receive the idempotent duplicate result.
func runP10Proxy(args []string) error {
	fs := flag.NewFlagSet("proxy", flag.ExitOnError)
	listen := fs.String("listen", "0.0.0.0:9443", "proxy listen address")
	backend := fs.String("backend", "", "backend base URL, for example https://192.168.189.138:8443")
	certFile := fs.String("cert", "", "TLS certificate for the proxy")
	keyFile := fs.String("key", "", "TLS private key for the proxy")
	caFile := fs.String("ca", "", "CA used to verify the real backend")
	_ = fs.Parse(args)
	if *backend == "" || *certFile == "" || *keyFile == "" || *caFile == "" {
		return fmt.Errorf("backend, cert, key and ca are required")
	}
	target, err := url.Parse(*backend)
	if err != nil {
		return err
	}
	caPEM, err := os.ReadFile(*caFile)
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return fmt.Errorf("CA file contains no certificates")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}}
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.Transport = transport
	var drop int32 = 1
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == protocol.PathReport && atomic.CompareAndSwapInt32(&drop, 1, 0) {
			request, err := http.NewRequestWithContext(r.Context(), r.Method, target.String()+r.URL.RequestURI(), r.Body)
			if err == nil {
				for key, values := range r.Header {
					for _, value := range values {
						request.Header.Add(key, value)
					}
				}
				response, err := transport.RoundTrip(request)
				if err == nil {
					_, _ = io.Copy(io.Discard, response.Body)
					_ = response.Body.Close()
				}
			}
			log.Printf("P10 proxy dropped first report response (request reached backend: %v)", err)
			if hijacker, ok := w.(http.Hijacker); ok {
				if conn, _, err := hijacker.Hijack(); err == nil {
					_ = conn.Close()
					return
				}
			}
			return
		}
		proxy.ServeHTTP(w, r)
	})
	server := &http.Server{
		Addr:              *listen,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      120 * time.Second,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
	}
	log.Printf("P10 proxy listening on %s -> %s", *listen, *backend)
	return server.ListenAndServeTLS(*certFile, *keyFile)
}
