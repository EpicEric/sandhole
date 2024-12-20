# Frequently Asked Questions

## How do I expose my service on multiple URLs (for example, `website.com` and `www.website.com`)?

```bash
ssh -R website.com:80:localhost:3000 -R www.website.com:80:localhost:3000 sandhole.com -p 2222
```

See ["Advanced Uses"](./advanced_uses.md#custom-domains) on how to add custom domains.

## How do I connect to a forwarded SSH server?

Use `ssh -J sandhole.com:2222 mysshserver.com -p 2222` (replace the ports with Sandhole's SSH port if not using the default `2222`).

If you'd like to avoid typing out the proxy jump command every time, make sure to edit your SSH config file (usually `~/.ssh/config`) and add the following entry:

```ssh-config
Host mysshserver.com
	ProxyJump sandhole.com:2222
	Port 2222
```

## How do I prevent multiple services from load-balancing?

With the `--load-balancing=deny` or `--load-balancing=replace` [CLI flag](./cli.md). This is currently a global setting.

## How do I force HTTP requests to get redirected to HTTPS?

With the `--force-https` [CLI flag](./cli.md). This is currently a global setting.

## How do I enable Websockets?

Websockets are always enabled for HTTP services.
