# Configuration

This is a list of the most important settings to be aware of. For a comprehensive list, refer to the [CLI options](./cli.md).

## Adding users and admins

In order to do anything useful with Sandhole, connections must be authenticated. The main way of doing this is by adding your users' public keys to the user keys directory.

By default, this will be `./deploy/user_keys/`, but it can be configured with the `--user-keys-directory` option. Once you add a public key, Sandhole will automatically pick up on the change, and allow that user to create remote port forwardings.

Similarly, there is a `./deploy/admin_keys/` directory (set by `--admin-keys-directory`), for users who should also have access to the [admin interface](./admin_interface.md) and [no quota restrictions](#restricting-resources-for-users).

### User permissions

Users with unrecognized SSH keys are still allowed to connect, in order to perform [local forwarding](./local_forwarding.mdrandom-subdomain-seed) to user-provided services. As such, these are the possible types of authentication:

| Authentication type | Connection method(s)    |
| ------------------- | ----------------------- |
| None                | Public key              |
| User                | Password¹ or public key |
| Admin               | Public key              |

¹ Optional password authentication with a [login API](#alternative-authentication-with-password).

And these are each of their capabilities:

| Authentication type | Local forwarding (proxy) | Remote forwading (reverse proxy) | Admin interface access |
| ------------------- | ------------------------ | -------------------------------- | ---------------------- |
| None                | ✅                       | ❌                               | ❌                     |
| User                | ✅                       | ✅²                              | ❌                     |
| Admin               | ✅                       | ✅                               | ✅                     |

² Remote forwarding by users is subject to restrictions, such as [service quotas](#service-quotas) and [rate limiting](#rate-limiting).

## Default ports

By default, Sandhole runs on ports 80, 443, and 2222. This assumes that your actual SSH server is running on port 22, and that no other services are listening on the HTTP/HTTPS ports.

However, it might be desirable to have Sandhole listen on port 22 instead. In order to keep your OpenSSH server running on a different port, edit the `Port` entry in `/etc/ssh/sshd_config`, then restart your SSH daemon.

Now you'll be able to run Sandhole on port 22:

```bash
sandhole --domain server.com --ssh-port 22
```

Similarly, you can change the port for the HTTP and HTTPS services, but note that using HTTPS on a port other than 443 will disable [ACME challenges](./tls_support.md#acme-support).

## Allow binding on any subdomains/ports

Without extra configuration, Sandhole will not let users bind to requested subdomains and ports, and will always allocate a random one instead.

If you wish to change the default behavior, and allow users to provide their own subdomains/ports to bind to, add the options `--allow-requested-subdomains` and `--allow-requested-ports`, respectively.

Otherwise, if you wish the subdomains to still be random, but persist between requests/disconnections, check out the `--random-subdomain-seed` option in the [command-line interface](./cli.md).

## Allow connecting to SSH via the HTTPS port

In some networks, outbound connections to 22 (or 2222) may be blocked by the operators. In Sandhole, it's possible to get around this with the `--connect-ssh-on-https-port` option.

Once you have configured it, users can then expose their services with the `-p 443` option:

```bash
ssh -R example:80:localhost:3000 sandhole.com.br -p 443
```

## Alternative authentication with password

In some scenarios, it makes more sense to authenticate users dynamically with a password, rather than manually adding public keys to a directory.

In order to support this, you can provide a URL to `--password-authentication-url`. This should be running an HTTP or HTTPS service, which must accept a JSON POST request containing the user's credentials as follows:

```json
{
  "user": "eric",
  "password": "super$ecret123",
  "remote_address": "[::ffff:10.0.5.32]:12703" // std::net::SocketAddr
}
```

Any 2xx status will signify a successful authentication.

## Restricting resources for users

### Service quotas

By default, users are able to bind as many services as they want. In order to limit this amount, Sandhole provides the `--quota-per-user` option, which must be a number greater than 0. The user's quota includes all services across HTTP, SSH, and TCP.

To enforce this quota across multiple connections, Sandhole considers a unique user to be any number of forwardings sharing _the same public key_. In the case of [password-authenticated users](#alternative-authentication-with-password), _their username_ will be considered instead.

The quota is not enforced for admin users.

### Rate limiting

You may also specify a rate limit on a user's combined services with the `--rate-limit-per-user` option, by passing the maximum amount of bytes per second such as `1MB`.

Read the section above on how Sandhole determines what is a unique user across multiple connections.

Rate limiting is not enforced for admin users.

### Profanity filtering

It's possible to disallow profanities from being generated by the random address assignment with the `--random-subdomain-filter-profanities` option. This applies to HTTP hosts and aliases.

You can also disable profanities from being requested with the `--requested-domain-filter-profanities` option, which may lead to false positives being denied.
