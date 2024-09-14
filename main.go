// Copyright 2024 Sergey Grankin
// Copyright 2022 Tailscale Inc & Contributors
// SPDX-License-Identifier: BSD-3-Clause

// tsnet-proxy exposes an HTTP server the tailnet.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"

	"golang.org/x/sync/errgroup"
	"tailscale.com/tailcfg"

	"tailscale.com/client/tailscale"
	"tailscale.com/tsnet"
	"tailscale.com/util/dnsname"
)

func main() {
	var (
		configDir = flag.String("config-dir", "", "Directory to use for tailnet state")
		hostname  = flag.String("hostname", "", "Hostname to use on the tailnet")
		httpAddr  = flag.String("http", "127.0.0.1:80", "Address to forward HTTP requests to")
		useHTTPS  = flag.Bool("https", true, "Serve over HTTPS if enabled on the tailnet")
		verbose   = flag.Bool("verbose", false, "Be verbose")
		proxyConf = proxyConfFlag("forward", "Forward extra ports.  FROM_PORT[:TO_ADDR]:TO_PORT[/NETWORK]")
	)
	flag.Parse()
	if *hostname == "" {
		log.Fatal("-hostname is required")
	}
	srv := &tsnet.Server{
		Hostname:     *hostname,
		Logf:         func(format string, args ...any) {},
		Dir:          *configDir,
		RunWebClient: true,
	}
	if *verbose {
		srv.Logf = log.Printf
	}

	if err := run(srv, *httpAddr, *useHTTPS, *proxyConf); err != nil {
		log.Fatal(err)
	}
}

func run(srv *tsnet.Server, httpAddr string, useHTTPS bool, proxyConf []proxyConf) error {
	ctx := context.Background()
	if err := srv.Start(); err != nil {
		return err
	}

	localClient, err := srv.LocalClient()
	if err != nil {
		return err
	}

	// Wait for tailscale to come up...
	if _, err := srv.Up(ctx); err != nil {
		return fmt.Errorf("tailcale up: %v", err)
	}
	status, err := localClient.Status(ctx)
	if err != nil {
		return fmt.Errorf("tailscale status: %v", err)
	}

	var handler http.Handler = &httputil.ReverseProxy{
		Director: func(r *http.Request) {
			r.URL.Scheme = "http"
			r.URL.Host = srv.Hostname
		},
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.Dial("tcp", httpAddr)
			},
		},
	}
	handler = setAuthHeaders(localClient, handler)

	enableTLS := useHTTPS && status.Self.HasCap(tailcfg.CapabilityHTTPS) && len(srv.CertDomains()) > 0
	fqdn := strings.TrimSuffix(status.Self.DNSName, ".")
	if useHTTPS && !enableTLS {
		return fmt.Errorf("HTTPS requested but unavailable; check your tailscale config")
	}

	g, ctx := errgroup.WithContext(ctx)
	if enableTLS {
		log.Printf("Listening on :443, Serving https://%s/ ...", fqdn)
		httpsHandler := handler
		g.Go(func() error {
			return listenHTTPS(srv, httpsHandler, ":443")
		})
		handler = redirectHandler(fqdn)
	}
	g.Go(func() error {
		log.Print("Listening on :80")
		return listenHTTP(srv, handler, ":80")
	})
	for _, pc := range proxyConf {
		g.Go(func() error {
			log.Printf("Proxying %+v", pc)
			return proxy(srv, pc.network, pc.listenAddr, pc.dialAddr)
		})
	}
	g.Go(func() error {
		// If any listener errors out, shut down the server (which in turn closes down all other listeners).
		<-ctx.Done()
		return srv.Close()
	})
	return g.Wait()
}

type proxyConf struct {
	network    string
	listenAddr string
	dialAddr   string
}

func proxyConfFlag(name, usage string) *[]proxyConf {
	r := regexp.MustCompile(`^(?P<port>\d+)(:(?P<addr>.+))?:(?P<toPort>\d+)(/(?P<network>\w+))?$`)
	value := &[]proxyConf{}
	flag.Func(name, usage, func(s string) error {
		matched := match(r, s)
		if matched == nil {
			return fmt.Errorf("value %q must match regexp %v", s, r)
		}
		if matched["network"] == "" {
			matched["network"] = "tcp"
		}
		if matched["addr"] == "" {
			matched["addr"] = "127.0.0.1"
		}
		conf := proxyConf{
			network:    matched["network"],
			listenAddr: ":" + matched["port"],
			dialAddr:   matched["addr"] + ":" + matched["toPort"],
		}
		*value = append(*value, conf)
		return nil
	})
	return value
}

func match(r *regexp.Regexp, s string) map[string]string {
	match := r.FindStringSubmatch(s)
	if match == nil {
		return nil
	}
	result := map[string]string{}
	for i, name := range r.SubexpNames() {
		if i != 0 && name != "" {
			result[name] = match[i]
		}
	}
	return result
}

// proxy forwards connections from listenAddr to dialAddr.
// All standard network types are supported.
func proxy(srv *tsnet.Server, network, listenAdr, dialAddr string) error {
	lis, err := srv.Listen(network, listenAdr)
	if err != nil {
		return err
	}
	defer lis.Close()
	for {
		conn1, err := lis.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				err = nil
			}
			return err
		}
		defer conn1.Close()
		log.Printf("Accepted connection on %s", listenAdr)
		conn2, err := net.Dial(network, dialAddr)
		if err != nil {
			return err
		}
		go func() {
			if err := pipe(conn1, conn2); err != nil {
				log.Printf("Error while piping %s->%s: %v", listenAdr, dialAddr, err)
			}
		}()
	}
}

// pipe connects two connections and bidirectionally copies data between them.
func pipe(conn1, conn2 net.Conn) error {
	defer conn1.Close()
	defer conn2.Close()

	g := errgroup.Group{}
	closingCopy := func(conn1, conn2 net.Conn) error {
		_, err := io.Copy(conn1, conn2)
		// If the connection can be partially closed, signal that there is no more data coming.
		if wc, ok := conn1.(interface {
			CloseWrite() error
		}); ok {
			wc.CloseWrite()
		}
		return err
	}
	g.Go(func() error { return closingCopy(conn1, conn2) })
	g.Go(func() error { return closingCopy(conn2, conn1) })
	return g.Wait()
}

func listenHTTPS(srv *tsnet.Server, handler http.Handler, addr string) error {
	httpsHandler := HSTS(handler)
	httpsListener, err := srv.ListenTLS("tcp", addr)
	if err != nil {
		return err
	}
	defer httpsListener.Close()
	if err := http.Serve(httpsListener, httpsHandler); err != nil {
		return err
	}
	return nil
}

func listenHTTP(srv *tsnet.Server, handler http.Handler, addr string) error {
	httpListener, err := srv.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer httpListener.Close()
	if err := http.Serve(httpListener, handler); err != nil {
		return err
	}
	return nil

}

// HSTS wraps the provided handler and sets Strict-Transport-Security header on
// responses. It inspects the Host header to ensure we do not specify HSTS
// response on non fully qualified domain name origins.
func HSTS(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, found := r.Header["Host"]
		if found {
			host := host[0]
			fqdn, err := dnsname.ToFQDN(host)
			if err == nil {
				segCount := fqdn.NumLabels()
				if segCount > 1 {
					w.Header().Set("Strict-Transport-Security", "max-age=31536000")
				}
			}
		}
		h.ServeHTTP(w, r)
	})
}

// redirectHandler returns the http.Handler for serving all plaintext HTTP
// requests. It redirects all requests to the HTTPs version of the same URL.
func redirectHandler(hostname string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, (&url.URL{Scheme: "https", Host: hostname, Path: r.URL.Path}).String(), http.StatusFound)
	})
}

// setAuthHeaders adds Tailscale-* headers populated with the authenticated user's info.
func setAuthHeaders(lc *tailscale.LocalClient, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		who, err := lc.WhoIs(r.Context(), r.RemoteAddr)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		r.Header.Set("Tailscale-Name", who.UserProfile.DisplayName)
		r.Header.Set("Tailscale-User", who.UserProfile.LoginName)
		r.Header.Set("Tailscale-Login", strings.Split(who.UserProfile.LoginName, "@")[0])
		r.Header.Set("Tailscale-Profile-Picture", who.UserProfile.ProfilePicURL)
		tailnet, _ := strings.CutPrefix(who.Node.Name, who.Node.ComputedName+".")
		r.Header.Set("Tailscale-Tailnet", tailnet)
		next.ServeHTTP(w, r)
	})
}
