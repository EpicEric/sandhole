# Local forwarding and aliasing

In addition to remote port forwarding, Sandhole also supports local port forwarding by default. This allows you to create SSH-based tunnels to connect to a service.

Given a remote service running as

```bash
ssh -R my.tunnel:3000:localhost:2000 sandhole.com -p 2222
```

Note that the server won't listen on port 3000; instead, you can establish a local forward to the port from your machine:

```bash
ssh -L 4000:my.tunnel:3000
```

Then you can access `localhost:4000`, and all traffic will be redirected to port 2000 on the remote service. It's almost like a VPN!

## Enforcing local forwarding

Local forwarding is always enabled for SSH hosts, and is conditionally enabled for TCP hosts that have a requested address different from `localhost`.

To enable local forwarding for HTTP hosts, pass either the `tcp-alias` or [the `allowed-fingerprints`](#restricting-access-to-local-forwardings) command to the remote forwarding command as follows:

```bash
ssh -R my.tunnel:80:localhost:8080 sandhole.com -p 2222 tcp-alias
```

## Restricting access to local forwardings

If you'd like to restrict which users can access your service, you can provide the allowed fingerprints as a comma-separated list at the end of the command, like so:

```bash
ssh -R my.tunnel:3000:localhost:2000 sandhole.com -p 2222 allowed-fingerprints=SHA256:GehKyA21BBK6eJCouziacUmqYDNl8BPMGG0CTtLSrbQ,SHA256:bwf4FDtNeZzFv8xHBzHJwRpDRxssCll8w2tCHFC9n1o
```

## Disabling local forwarding

The administrator can disable all local forwardings with the [`--disable-aliasing` CLI flag](./cli.md).
