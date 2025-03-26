# Advanced options

There are multiple options that you can pass to Sandhole when requesting a remote forwarding, such as via OpenSSH's CLI. You can also combine them by passing them in a single command, separated by spaces. Here is a list of the options with examples:

## `allowed-fingerprints`

This option requires certain SSH key fingerprints for aliasing. See ["Restricting access to local forwardings"](./local_forwarding.md#restricting-access-to-local-forwardings).

```bash
ssh -p 2222 -R my.tunnel:3000:localhost:2000 sandhole.com.br allowed-fingerprints=SHA256:GehKyA21BBK6eJCouziacUmqYDNl8BPMGG0CTtLSrbQ,SHA256:bwf4FDtNeZzFv8xHBzHJwRpDRxssCll8w2tCHFC9n1o
```

## `tcp-alias`

This option forces an HTTP remote forwarding request to be an alias instead of a proxy. See ["Enforcing aliasing"](./local_forwarding.md#enforcing-aliasing).

```bash
ssh -p 2222 -R my.tunnel:80:localhost:8080 sandhole.com.br tcp-alias
```

## `force-https`

This option forces proxied HTTP requests to be redirected to HTTPS.

```bash
ssh -p 2222 -R my.tunnel:80:localhost:8080 sandhole.com.br force-https
```

## `http2`

This option tells Sandhole to serve HTTP/2 instead of HTTP/1.1 for your service. This option only works over HTTPS, so you may want to also set `force-https`.

```bash
ssh -p 2222 -R my.tunnel:80:localhost:8080 sandhole.com.br http2 force-https
```

## `sni-proxy`

This option tells Sandhole that it should use your provided TLS backend. This guarantees that Sandhole cannot see unencrypted traffic. This option only works over HTTPS, so you may want to also set `force-https`.

```bash
ssh -p 2222 -R my.tunnel:80:localhost:8080 sandhole.com.br sni-proxy force-https
```

## `ip-allowlist` / `ip-blocklist`

These options allow you to limit the IP ranges for incoming proxy/alias connections.

```bash
ssh -p 2222 -R website.com:80:localhost:3000 sandhole.com.br ip-allowlist=10.0.0.0/8 ip-blocklist=10.1.0.0/16
```
