# Frequently asked questions

## How do I expose my service on multiple custom domains (such as `example.com` and `www.example.com`)?

```bash
ssh -p 2222 -R example.com:80:localhost:3000 -R www.example.com:80:localhost:3000 sandhole.com.br
```

## How do I connect to a forwarded SSH server?

Use `ssh -p 2222 -J sandhole.com.br:2222 mysshserver.com` (replace the ports with Sandhole's SSH port if not using the default `2222`).

If you'd like to avoid typing out the proxy jump command every time, make sure to edit your SSH config file (usually `~/.ssh/config`) and add the following entry (changing the port where appropriate):

```ssh-config
Host mysshserver.com
	ProxyJump sandhole.com.br:2222
	Port 2222
```

## How do I enable Websockets?

Websockets are always enabled for HTTP services.

## How do I retrieve proxy information for my HTTP service?

You can use the standard proxy headers set by Sandhole:

- `X-Forwarded-For`: Client IP address.
- `X-Forwarded-Host`: Original hostname header.
- `X-Forwarded-Proto`: Protocol (`http` or `https`).
- `X-Forwarded-Port`: Proxy port number.

## What if I need to run another HTTP/HTTPS service on the machine instead of Sandhole?

It's simple: just let Sandhole take care of that for you! Nothing stops you from connecting to Sandhole on localhost, and just like any reverse proxy, it will redirect the traffic appropriately for you.

## How do I squeeze out more performance?

If both client and server support hardware instructions for AES (i.e. most x64 processors), you should prefer the AES-GCM cipher by passing the `-c aes256-gcm@openssh.com` flag to your OpenSSH client, as it's generally faster. For ARM processors running a modern version of OpenSSH, `-c chacha20-poly1305@openssh.com` might be the faster cipher out of the two options.

Another option is to use compression for HTTP services (such as gzip), in order to reduce the amount of data that has to be encrypted.

## How do I disable HTTP/TCP/aliasing?

With the `--disable--http`, `--disable-tcp`, and `--disable-aliasing` [CLI flags](./cli.md) respectively. Note that you cannot disable all three at once, as that would remove all of Sandhole's functionality. You can also disable HTTPS and SNI with `--disable-https` and `--disable-sni`, respectively.

## How do I prevent multiple services from load-balancing?

With the `--load-balancing=deny` or `--load-balancing=replace` [CLI flag](./cli.md).

## How do I force HTTP requests to get redirected to HTTPS?

You may do so globally with the `--force-https` [CLI flag](./cli.md), or [per service](./advanced_options.md#force-https) by passing `force-https` on the tunneling connection.

## How do I allow/block certain IP ranges?

You may do so globally with the `--ip-allowlist` and `--ip-blocklist` [CLI flags](./cli.md) respectively, or [per service](./advanced_options.md#ip-allowlist--ip-blocklist) by passing `ip-allowist=...` and/or `ip-blocklist=...` on the tunneling connection.
