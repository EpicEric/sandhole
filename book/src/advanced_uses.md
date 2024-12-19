# Advanced uses

## Connecting to the HTTPS port

In some networks, outbound connections to 22 (or 2222) may be blocked by the operator. In Sandhole, it's possible to get around this with the `--connect-ssh-on-https-port` option.

Once your administrator has configured it, you can then expose your services with:

```bash
ssh -R test:80:localhost:3000 server.com -p 443
```

## Local forwarding and aliasing

In addition to remote port forwarding, Sandhole also supports local port forwarding. This allows you to create SSH-based tunnels to connect to a service.

Given a remote service running as

```bash
ssh -R my.tunnel:3000:localhost:2000 server.com -p 2222
```

Note that the server won't listen on port 3000; instead, you can establish a local forward to the port from your machine:

```bash
ssh -L 4000:my.tunnel:3000
```

Then you can access `localhost:4000`, and all traffic will be redirected to port 2000 on the remote service. It's almost like a VPN!

If you'd like to restrict which users can access your service, you can provide the allowed fingerprints as a comma-separated list at the end of the command, like so:

```bash
ssh -R my.tunnel:3000:localhost:2000 server.com -p 2222 allowed-fingerprints=SHA256:GehKyA21BBK6eJCouziacUmqYDNl8BPMGG0CTtLSrbQ,SHA256:bwf4FDtNeZzFv8xHBzHJwRpDRxssCll8w2tCHFC9n1o
```

This only works for TCP aliases, and will be ignored for HTTP.

## Custom domains

You can also use your custom domains with Sandhole. For this, you'll need your SSH key's fingerprint and control over your domain's DNS.

For the former, you can run `ssh-keygen -lf /path/to/private/key` and take note of the second field - it will look something like:

```plaintext
SHA256:bwf4FDtNeZzFv8xHBzHJwRpDRxssCll8w2tCHFC9n1o
```

Then, add the following entries to your DNS (assuming that your custom domain is `my.domain.net`):

| Type  | Domain                              | Data                                                          |
| ----- | ----------------------------------- | ------------------------------------------------------------- |
| CNAME | <pre>my.domain.net</pre>            | <pre>server.com</pre>                                         |
| TXT   | <pre>\_sandhole.my.domain.net</pre> | <pre>SHA256:bwf4FDtNeZzFv8xHBzHJwRpDRxssCll8w2tCHFC9n1o</pre> |

This instructs your DNS to redirect requests to Sandhole, and tells Sandhole to authorize your SSH key for the given domain, respectively.

If you need to use multiple keys for the same domain, simply add a TXT record for each one.

### HTTPS support

If your administrator has configured [ACME support](./tls_support.md#acme-support), you don't need any extra steps. HTTPS will be automatically available for you.

However, if you require DNS challenges for your domain's certification for any reason, and your administrator is running [dnsrobocert](./tls_support.md), you can simply set another DNS entry:

| Type  | Domain                                    | Data                                                 |
| ----- | ----------------------------------------- | ---------------------------------------------------- |
| CNAME | <pre>\_acme-challenge.my.domain.net</pre> | <pre>\_acme-challenge.my.domain.net.server.com</pre> |

This lets dnsrobocert manage the ACME challenge for you.
