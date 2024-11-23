# Advanced uses

## Local forwarding

In addition to remote port forwarding, Sandhole also supports local port forwarding. This allows you to create SSH-based tunnels to connect to a service.

Given a remote service running as

```shell
ssh -R 3000:localhost:2000 server.com -p 2222
```

You can establish a local forward of the port on your machine:

```shell
ssh -L 4000:localhost:3000
```

Then you can access `localhost:4000`, and all traffic will be redirected to port 2000 on the remote service.

Currently, there are no authentication options for local forwarding, but this is a planned feature.

## Custom domains

You can also use your custom domains with Sandhole. For this, you'll need your SSH key's fingerprint and control over your domain's DNS.

For the former, you can run `ssh-keygen -lf /path/to/private/key` and take note of the second field - it will look something like:

```plaintext
SHA256:bwf4FDtNeZzFv8xHBzHJwRpDRxssCll8w2tCHFC9n1o
```

Then, add the following entries to your DNS (assuming that your domain is `my.domain.net`):

| Type  | Domain                    | Data                                                 |
| ----- | ------------------------- | ---------------------------------------------------- |
| CNAME | `my.domain.net`           | `server.com`                                         |
| TXT   | `_sandhole.my.domain.net` | `SHA256:bwf4FDtNeZzFv8xHBzHJwRpDRxssCll8w2tCHFC9n1o` |

This instructs your DNS to redirect requests to Sandhole, and tells Sandhole to authorize your SSH key for the given domain, respectively.

If you need to use multiple keys for the same domain, simply add a TXT record for each one.
