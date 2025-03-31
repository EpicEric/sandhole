# TLS support

Sandhole supports TLS signing out of the box, including ACME challenges via TLS-ALPN-01 for custom domains.

However, especially for your main domain (eg. `*.sandhole.com.br`), it's recommended that you set up a tool for wildcard certification via DNS. Here are some options supported by Sandhole:

- For [Agnos](https://github.com/krtab/agnos), Sandhole requires certificates to live in `./<root dir>/<some name>/fullchain.pem` and their respective keys in `./<root dir>/<some name>/privkey.pem` - for example, `./agnos/sandhole.com.br/fullchain.pem` and `./agnos/sandhole.com.br/privkey.pem`. In this case, Sandhole can access the certificates via:

```bash
sandhole --domain sandhole.com.br --certificates-directory ./agnos
```

- For [dnsrobocert](https://adferrand.github.io/dnsrobocert/), Sandhole matches its format directly. Assuming that the output of dnsrobocert is in `./letsencrypt`, Sandhole can access the certificates via:

```bash
sandhole --domain sandhole.com.br --certificates-directory ./letsencrypt/live
```

## ACME support

ACME allows you to generate certificates for user-provided domains automatically, without having to edit your configuration for each one.

Adding ACME support is as simple as adding your contact e-mail address via `--acme-contact-email you@your.email.com`, but first, make sure that you agree to the [Let's Encrypt Subscriber Agreement](https://letsencrypt.org/repository/). Sandhole will automatically manage the cache for your account and any certificates generated this way.
