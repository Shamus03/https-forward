package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

var (
	flagConfig = flag.String("config", "/etc/https-forward", "config file to read")
)

const (
	forwardedFor = "X-Forwarded-For"
)

func main() {
	flag.Parse()

	config := &configHolder{config: make(map[string]hostConfig)}
	err := config.Read(*flagConfig)
	if err != nil {
		log.Fatalf("could not read config: %v", err)
	}

	// listen to SIGHUP for config changes
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGHUP)
	go func() {
		for range c {
			err := config.Read(*flagConfig)
			if err != nil {
				log.Fatalf("could not read config: %v", err)
			}
		}
	}()

	hostPolicy := func(c context.Context, host string) error {
		if _, ok := config.For(host); !ok {
			return fmt.Errorf("disallowing host: %v", host)
		}
		log.Printf("allowing: %v", host)
		return nil
	}

	hostRouter := func(w http.ResponseWriter, r *http.Request) {
		hc, ok := config.For(r.Host)
		if !ok {
			// should never get here: SSL cert should not be generated
			w.WriteHeader(http.StatusNotFound)
			return
		}

		// https for a day
		sec := 86400
		w.Header().Set("Strict-Transport-Security", fmt.Sprintf("max-age=%d; includeSubDomains", sec))

		// auth if needed
		if hc.auth {
			username, password, ok := r.BasicAuth()
			if !ok {
				log.Printf("sending WWW-Authenticate for: %s%s", r.Host, r.URL.Path)
				v := fmt.Sprintf(`Basic realm="%s"`, r.Host)
				w.Header().Set("WWW-Authenticate", v)
				http.Error(w, "", http.StatusUnauthorized)
				return
			}
			if allowed := hc.Allow(username, password); !allowed {
				http.Error(w, "", http.StatusForbidden)
				return
			}
		}

		// success
		if hc.proxy != nil {
			hc.proxy.ServeHTTP(w, r)
			return
		}

		// top-level domains don't do anything
		if r.URL.Path == "/" {
			fmt.Fprintf(w, `¯\_(ツ)_/¯`)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}

	certManager := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache("/tmp/autocert"),
		HostPolicy: hostPolicy,
	}
	server := &http.Server{
		Addr:    ":https",
		Handler: http.HandlerFunc(hostRouter),
		TLSConfig: &tls.Config{
			GetCertificate: certManager.GetCertificate,
			NextProtos:     []string{acme.ALPNProto},
		},
	}

	go func() {
		//h := certManager.HTTPHandler(nil)
		//log.Fatal(http.ListenAndServe(":http", h))
	}()

	log.Fatal(server.ListenAndServeTLS("", ""))
}

