# TLS support

Sandhole supports TLS signing out of the box, including ACME challenges via TLS-ALPN-01 for custom domains.

However, especially for your main domain, it's recommended that you set up a tool like [dnsrobocert](https://github.com/adferrand/dnsrobocert) to handle the wildcard certification via DNS. Sandhole already matches dnsrobocert's output directly. Please see its documentation to set it up yourself.

Assuming that the output of dnsrobocert is `./letsencrypt`, Sandhole can then read the certificates via:

```bash
sandhole --domain sandhole.com --certificates-directory ./letsencrypt/live
```

## ACME support

Adding ACME support is as simple as adding your contact e-mail address via `--acme-contact-email you@your.email.com`, but first, make sure that you agree to the Let's Encrypt Subscriber Agreement ([available here](https://letsencrypt.org/repository/)). Sandhole will automatically manage the cache for your account and any certificates generated this way.
