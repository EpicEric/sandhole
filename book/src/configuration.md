# Configuration

This is a list of the most important default settings to be aware of. For a comprehensive list, refer to the [CLI options](./cli.md).

## Adding users and admins

In order to do anything useful with Sandhole, connections must be authenticated. The main way of doing this is by adding your users' public keys to the user keys directory.

By default, this will be `./deploy/user_keys/`, but it can be configured with the `--user-keys-directory` option. Once you add a public key, Sandhole will automatically pick up on the change, and allow that user to create remote port forwardings.

Similarly, there is a `./deploy/admin_keys/` directory (set by `--admin-keys-directory`), for users who should also have access to the [admin interface](./admin_interface.md).

## Default ports

By default, Sandhole runs on ports 80, 443, and 2222. This assumes that your actual SSH server is running on port 22, and that no other services are listening on the HTTP/HTTPS ports.

However, it might be more desirable to have Sandhole listen on port 22 instead. In order to keep your SSH server running on a different port, edit the port in `/etc/ssh/sshd_config`, then restart your SSH daemon.

Now you'll be able to run Sandhole on port 22:

```shell
sandhole --domain server.com --ssh-port 22
```

## Allow binding on any subdomains/ports

Without extra configuration, Sandhole will not let users bind to requested subdomains and ports, and will always allocate a random one instead.

If you wish to change the default behavior, and allow users to provide their own subdomains/ports to bind to, add the options `--allow-provided-subdomains` and `--allow-requested-ports`, respectively.

## Alternative authentication with password

In some scenarios, it makes more sense to authenticate users dynamically with a password, rather than adding and removing keys from a directory.

For such use cases, you can provide a URL to `--password-authentication-url`. This should be running a service which accepts a POST request with the following JSON body containing the user's credentials, and returns 2xx on successful authentication:

```json
{
  "user": "...",
  "password": "..."
}
```
