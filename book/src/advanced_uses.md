# Advanced uses

## Connecting to SSH via the HTTPS port

In some networks, outbound connections to 22 (or 2222) may be blocked by the operator. In Sandhole, it's possible to get around this with the `--connect-ssh-on-https-port` option.

Once your administrator has configured it, you can then expose your services with:

```bash
ssh -R example:80:localhost:3000 sandhole.com -p 443
```

## Custom domains

You can also use your custom domains with Sandhole. For this, you'll need your SSH key's fingerprint and control over your domain's DNS.

For the former, you can run `ssh-keygen -lf /path/to/private/key` and take note of the second field - it will look something like:

```plaintext
SHA256:bwf4FDtNeZzFv8xHBzHJwRpDRxssCll8w2tCHFC9n1o
```

Then, add the following entries to your DNS server (assuming that your custom domain is `my.domain.net`):

| Type  | Domain                              | Data                                                          |
| ----- | ----------------------------------- | ------------------------------------------------------------- |
| CNAME | <pre>my.domain.net</pre>            | <pre>sandhole.com</pre>                                       |
| TXT   | <pre>\_sandhole.my.domain.net</pre> | <pre>SHA256:bwf4FDtNeZzFv8xHBzHJwRpDRxssCll8w2tCHFC9n1o</pre> |

This instructs your DNS server to redirect requests to Sandhole, and tells Sandhole to authorize your SSH key for the given domain, respectively.

If you need to use multiple keys for the same domain, simply add a TXT record for each one.

Then, expose your service at the given domain:

```bash
ssh -R my.domain.net:80:localhost:3000 sandhole.com -p 2222
```

### HTTPS support

If your administrator has configured [ACME support](./tls_support.md#acme-support), you don't need any extra steps to enable HTTPS support. It will be automatically provisioned for your custom domain.

However, if you require DNS challenges for your domain's certification for any reason, and your administrator is running [dnsrobocert](./tls_support.md), you can simply set another DNS entry:

| Type  | Domain                                    | Data                                                   |
| ----- | ----------------------------------------- | ------------------------------------------------------ |
| CNAME | <pre>\_acme-challenge.my.domain.net</pre> | <pre>\_acme-challenge.my.domain.net.sandhole.com</pre> |

This lets dnsrobocert manage the ACME challenge for you, as long as the admin updates dnsrobocert's configuration with [`follow_cnames`](https://adferrand.github.io/dnsrobocert/configuration_reference.html#follow-cnames).
