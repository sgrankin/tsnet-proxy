// tsnet-proxy exposes an HTTP server the tailnet.
package main

import (
	"context"
	"flag"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
	"tailscale.com/util/dnsname"
)

var (
	hostname = flag.String("hostname", "", "hostname to use on the tailnet")
	toAddr   = flag.String("to-addr", "127.0.0.1:80", "address to forward requests to")
	toNet    = flag.String("to-net", "tcp", "type of to-addr")
	useHTTPS = flag.Bool("https", true, "serve golink over HTTPS if enabled on tailnet")
	verbose  = flag.Bool("verbose", false, "be verbose")
)

func main() {
	flag.Parse()
	if *hostname == "" {
		log.Fatal("-hostname is required")
	}

	srv := &tsnet.Server{
		Hostname: *hostname,
	}
	defer srv.Close()

	localClient, err := srv.LocalClient()
	if err != nil {
		log.Panic(err)
	}

	ctx := context.Background()
	status, err := localClient.Status(ctx)
	if err != nil {
		log.Panic(err)
	}

	enableTLS := *useHTTPS && status.Self.HasCap(tailcfg.CapabilityHTTPS) && len(srv.CertDomains()) > 0
	fqdn := strings.TrimSuffix(status.Self.DNSName, ".")

	var httpHandler http.Handler = &httputil.ReverseProxy{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.Dial(*toNet, *toAddr)
			},
		},
	}

	if enableTLS {
		httpsHandler := HSTS(httpHandler)
		httpHandler = redirectHandler(fqdn)

		httpsListener, err := srv.ListenTLS("tcp", ":443")
		if err != nil {
			log.Panic(err)
		}
		defer httpsListener.Close()
		log.Println("Listening on :443")
		go func() {
			log.Printf("Serving https://%s/ ...", fqdn)
			if err := http.Serve(httpsListener, httpsHandler); err != nil {
				log.Fatal(err)
			}
		}()
	}

	httpListener, err := srv.Listen("tcp", ":80")
	if err != nil {
		log.Panic(err)
	}
	defer httpListener.Close()
	log.Println("Listening on :80")
	if err := http.Serve(httpListener, httpHandler); err != nil {
		log.Panic(err)
	}
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
