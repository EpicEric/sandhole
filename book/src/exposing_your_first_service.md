# Exposing your first service

Now that you have a Sandhole instance running, and you [authorized your public key](./configuration.md#adding-users-and-admins), you can expose a local service through Sandhole. Assuming that your local HTTP service is running on port 3000, and that Sandhole is listening on `sandhole.com:2222`, all you have to do is run

```bash
ssh -i /your/private/key -R 80:localhost:3000 sandhole.com -p 2222
```

Yep, that's it! Sandhole will log that HTTP is being served for you on a certain subdomain, and you can access the provided URL to see that your service is available to the public.

For HTTP and HTTPS services, Websockets work out of the box.

## Requesting multiple tunnels

You can request tunnels for several services in a single SSH command.

```bash
ssh -i /your/private/key -R 80:localhost:3000 -R 80:localhost:4000 -R 22:localhost:5000 sandhole.com -p 2222
```

## Requesting a particular subdomain/port

After the server owner [allows binding on any subdomain/port](configuration.md#allow-binding-on-any-subdomainsports), it's possible to configure which will be assigned to you.

For example, to bind under `test.sandhole.com`, we could use either of these commands:

```bash
ssh -i /your/private/key -R test:80:localhost:3000 sandhole.com -p 2222
# -- OR --
ssh -i /your/private/key -R test.sandhole.com:80:localhost:3000 sandhole.com -p 2222
```

And if we'd like to bind to a specific port, say 4321:

```bash
ssh -i /your/private/key -R 4321:localhost:3000 sandhole.com -p 2222
# -- OR --
ssh -i /your/private/key -R localhost:4321:localhost:3000 sandhole.com -p 2222
```

## Connecting with user + password

If you'd like to connect with a password instead of your public key, make sure that [HTTP(S) login](./configuration.md#alternative-authentication-with-password) has been enabled by the administrator, then run:

```bash
ssh -o PubkeyAuthentication=no -o PreferredAuthentications=password username@sandhole.com -p 2222 ...
```

## Automatic reconnection

If you'd like to have persistent tunnels, use a tool like `autossh` with the `-M 0` option to automatically reconnect when disconnected. Note that you'll be assigned a new subdomain/port if the option above is not enabled, depending on the server configuration.
