# tsnet-proxy

Using [tsnet](https://tailscale.com/kb/1244/tsnet), the proxy presents a service node on your network.

- HTTP (or HTTPS) traffic is forwarded to a specific port.
- Headers are attached with the authenticated tailscale user, so you can use this for auth.
- Auxiliary ports may be forwarded.

## Installation

`go install sgrankin.dev/tsnet-proxy@latest`

## Usage

```
Usage of tsnet-proxy:
  -config-dir string
        Directory to use for tailnet state
  -forward value
        Forward extra ports.  FROM_PORT[:TO_ADDR]:TO_PORT[/NETWORK]
  -hostname string
        Hostname to use on the tailnet
  -http string
        Address to forward HTTP requests to (default "127.0.0.1:80")
  -https
        Serve over HTTPS if enabled on the tailnet (default true)
  -verbose
        Be verbose
```

### Example: Gerrit

```sh
%h/go/bin/tsnet-proxy 
    -config-dir=${HOME}/.config/gerrit 
    -hostname=gerrit 
    -http=localhost:10971 
    -forward=22:29418 
    -https
```

```
; cat gerrit.config 
[gerrit]
        canonicalWebUrl = http://gerrit/
[auth]
        type = http
        httpHeader = Tailscale-Login
        httpDisplaynameHeader = Tailscale-Name

[sshd]
        listenAddress = 127.0.0.1:29418
        advertisedAddress = gerrit

[httpd]
        listenUrl = http://127.0.0.1:10971/

```

### Example: Grafana

```sh
%h/go/bin/tsnet-proxy 
    -config-dir=${HOME}/.config/grafana 
    -hostname=grafana 
    -http=localhost:3000 
    -https
```

```
; cat grafana.ini
[auth.proxy]
auto_sign_up = true
enable_login_token = true
enabled = true
header_name = Tailscale-Login
header_property = username
headers = Name:Tailscale-Name
whitelist = 127.0.0.1
```
