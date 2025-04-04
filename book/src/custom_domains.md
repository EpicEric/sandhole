# Custom domains

You can also use your custom domains with Sandhole. For this, you'll need your SSH key's fingerprint and control over your domain's DNS.

For the former, you can run `ssh-keygen -lf /path/to/private/key` and take note of the second field - it will look something like:

```plaintext
SHA256:bwf4FDtNeZzFv8xHBzHJwRpDRxssCll8w2tCHFC9n1o
```

Then, add the following entries to your DNS server (assuming that your custom domain is `my.domain.net`):

| Type  | Domain                              | Data                                                          |
| ----- | ----------------------------------- | ------------------------------------------------------------- |
| CNAME | <pre>my.domain.net</pre>            | <pre>sandhole.com.br</pre>                                    |
| TXT   | <pre>\_sandhole.my.domain.net</pre> | <pre>SHA256:bwf4FDtNeZzFv8xHBzHJwRpDRxssCll8w2tCHFC9n1o</pre> |

This instructs your DNS server to redirect requests to Sandhole, and tells Sandhole to authorize your SSH key for the given domain, respectively.

If you need to allow multiple keys for the same domain, simply add a TXT record for each one.

Then, expose your service at the given domain:

```bash
ssh -p 2222 -R my.domain.net:80:localhost:3000 sandhole.com.br
```

## HTTPS support for custom domains

If your administrator has configured [ACME support](./tls_support.md#acme-support), you don't need any extra steps to enable HTTPS support. It will be automatically provisioned for your custom domain.

However, if you require DNS challenges for your domain's certification for any reason, and your administrator is running [Agnos](./tls_support.md), you can simply set another DNS entry:

| Type | Domain                                    | Data                                |
| ---- | ----------------------------------------- | ----------------------------------- |
| NS   | <pre>\_acme-challenge.my.domain.net</pre> | <pre>agnos-ns.sandhole.com.br</pre> |

This lets Agnos manage the ACME challenge for you, as long as the admin updates [Agnos's configuration](https://github.com/krtab/agnos#agnos-configuration) with your domain.
