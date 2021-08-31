package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/kardianos/service"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

var (
	flagHSTS = flag.Duration("hsts", time.Hour*24, "duration for HSTS header")
)

const (
	forwardedFor = "X-Forwarded-For"
)

var (
	flagConfig *string
	flagCache  *string
)

func main() {
	svcFlag := flag.String("service", "", "Control the system service.")

	// configure flagConfig, in snap use common across revisions
	if snapCommon := os.Getenv("SNAP_COMMON"); snapCommon != "" {
		configPath := path.Join(snapCommon, "config")
		flagConfig = &configPath
	} else {
		flagConfig = flag.String("config", "/etc/https-forward", "config file to read")
	}

	// configure *flagCache, in SNAP mode just use its semi-permanent cache
	if snapData := os.Getenv("SNAP_DATA"); snapData != "" {
		cachePath := path.Join(snapData, "cache")
		flagCache = &cachePath
	} else {
		flagCache = flag.String("cache", "/tmp/autocert", "cert cache directory, blank for memory")
	}

	flag.Parse()

	svcConfig := &service.Config{
		Name:        "https-forward",
		DisplayName: "https-forward",
		Description: "external https reverse-proxy",
		Arguments: []string{
			"--config", "/Apps/https-forward/config",
		},
	}

	prg := &program{}
	s, err := service.New(prg, svcConfig)
	if err != nil {
		log.Fatal(err)
	}
	logger, err = s.Logger(nil)
	if err != nil {
		log.Fatal(err)
	}

	if len(*svcFlag) != 0 {
		err := service.Control(s, *svcFlag)
		if err != nil {
			logger.Infof("Valid actions: %q\n", service.ControlAction)
			log.Fatal(err)
		}
		return
	}

	if err = s.Run(); err != nil {
		logger.Error(err)
	}
}

var logger service.Logger

type program struct{}

func (p *program) Start(s service.Service) error {
	// Start should not block. Do the actual work async.
	go p.run()
	return nil
}

func (p *program) run() {
	logger.Infof("config=%v, cache=%v", *flagConfig, *flagCache)

	config := &configHolder{config: make(map[string]hostConfig)}
	err := config.Read(*flagConfig)
	if err != nil {
		log.Fatalf("could not read config: %v", err)
	}

	reloadConfig := func() {
		logger.Info("reloading config")
		err := config.Read(*flagConfig)
		if err != nil {
			logger.Errorf("could not read config: %v", err)
		}
	}

	// listen to SIGHUP for config changes
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGHUP)
	go func() {
		for range c {
			reloadConfig()
		}
	}()

	// watch file changes
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		logger.Errorf("set up watcher: %v", err)
		return
	}
	defer watcher.Close()
	go func() {
		for {
			select {
			case event := <-watcher.Events:
				logger.Infof("config file changed: %v\n", event)
				reloadConfig()
			case err := <-watcher.Errors:
				logger.Errorf("config file watch error: %v\n", err)
			default:
				return
			}
		}
	}()
	if err := watcher.Add(*flagConfig); err != nil {
		logger.Errorf("failed to watch config file: %v", err)
		return
	}

	hostPolicy := func(c context.Context, host string) error {
		if _, ok := config.For(host); !ok {
			return fmt.Errorf("disallowing host: %v", host)
		}
		return nil
	}

	hostRouter := func(w http.ResponseWriter, r *http.Request) {
		host := stripPort(r.Host)
		hc, ok := config.For(host)
		if !ok {
			// should never get here: SSL cert should not be generated
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// set https-only
		sec := int((*flagHSTS).Seconds())
		w.Header().Set("Strict-Transport-Security", fmt.Sprintf("max-age=%d; includeSubDomains", sec))

		// auth if needed
		if hc.auth {
			username, password, ok := r.BasicAuth()
			if !ok {
				v := fmt.Sprintf(`Basic realm="%s"`, host)
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
		HostPolicy: hostPolicy,
	}
	if *flagCache != "" {
		certManager.Cache = autocert.DirCache(*flagCache)
	}
	server := &http.Server{
		Addr:    ":https",
		Handler: http.HandlerFunc(hostRouter),
		TLSConfig: &tls.Config{
			GetCertificate: certManager.GetCertificate,
			NextProtos:     []string{acme.ALPNProto},
		},
	}

	die := make(chan struct{})

	go func() {
		if err := http.ListenAndServe(":http", http.HandlerFunc(handleRedirect)); err != nil && err != http.ErrServerClosed {
			logger.Errorf("http.ListenAndServe: %v", err)
		}
		close(die)
	}()

	go func() {
		if err := server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			logger.Errorf("server.ListenAndServeTLS: %v", err)
			return
		}
		close(die)
	}()

	<-die
}

func (p *program) Stop(s service.Service) error {
	// Stop should not block. Return with a few seconds.
	return nil
}

func handleRedirect(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" || r.Method == "HEAD" {
		target := "https://" + stripPort(r.Host) + r.URL.RequestURI()
		http.Redirect(w, r, target, http.StatusFound)
	} else {
		http.Error(w, "", http.StatusBadRequest)
	}
}

func stripPort(hostport string) string {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport
	}
	return host
}
