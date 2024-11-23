# Exposing your first service

Now that you have a Sandhole instance running, and you [authorized your public key](./configuration.md#adding-users-and-admins), you can expose a local service through Sandhole. Assuming that your local HTTP service is running on port 3000, and that Sandhole is listening on `server.com:2222`, all you have to do is run

```shell
ssh -R 80:localhost:3000 server.com -p 2222
```

Yep, that's it! Sandhole will log that HTTP is being served for you, and you can access the provided URL to see that your service is available to the public.

For HTTP and HTTPS services, Websockets work out of the box.

## Requesting multiple tunnels

You can request tunnels for several services in a single SSH command.

```shell
ssh -R 80:localhost:3000 -R 80:localhost:4000 -R 22:localhost:5000 server.com -p 2222
```

## Requesting a particular subdomain/port

After you [allow binding on any subdomain/port](configuration.md#allow-binding-on-any-subdomainsports), it's possible to configure which of these will be assigned to you.

For example, to bind under `test.server.com`, we could use either of these commands:

```shell
ssh -R test:80:localhost:3000 server.com -p 2222
ssh -R test.server.com:80:localhost:3000 server.com -p 2222
```

And if we'd like to bind to a specific port, say 4321:

```shell
ssh -R 4321:localhost:3000 server.com -p 2222
```

### Automatic reconnection

If you'd like to have persistent tunnels, use a tool like `autossh` with the `-M 0` option to automatically reconnect when disconnected. Note that you'll be assigned a new subdomain/port if the option above is not enabled, depending on the server configuration.