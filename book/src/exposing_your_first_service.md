# Exposing your first service

Once you have [an authorized public key](./configuration.md#adding-users-and-admins) in Sandhole, you can expose a local service. Assuming that your local HTTP service is running on port 3000, and that Sandhole is listening on `sandhole.com.br:2222`, all you have to do is run:

```bash
ssh -i /your/private/key -p 2222 -R 80:localhost:3000 sandhole.com.br
```

Yep, that's it! Sandhole will log that HTTP is being served for you on a certain subdomain, and you can access the URL printed to the console to see that your service is available to the public.

You'll also receive logs about each incoming HTTP request if the administrator hasn't disabled the logging option.

## Requesting multiple tunnels

You can request tunnels for several services in a single SSH command.

```bash
ssh -i /your/private/key -p 2222 -R 80:localhost:3000 -R 80:localhost:4000 -R 22:localhost:5000 sandhole.com.br
```

## Requesting a particular subdomain/port

After the server owner [allows binding on any subdomain/port](configuration.md#allow-binding-on-any-subdomainsports), it's possible to configure which will be assigned to you.

For example, to bind under `test.sandhole.com.br`, we could use either of these commands:

```bash
ssh -i /your/private/key -p 2222 -R test:80:localhost:3000 sandhole.com.br
#
# -- OR --
#
ssh -i /your/private/key -p 2222 -R test.sandhole.com.br:80:localhost:3000 sandhole.com.br
```

And if we'd like to bind to a specific port, say 4321:

```bash
ssh -i /your/private/key -p 2222 -R 4321:localhost:3000 sandhole.com.br
#
# -- OR --
#
ssh -i /your/private/key -p 2222 -R localhost:4321:localhost:3000 sandhole.com.br
```

## Connecting with user + password

If you'd like to connect with a password instead of your public key, make sure that [password authentication](./configuration.md#alternative-authentication-with-password) has been enabled by the administrator, then run:

```bash
ssh -p 2222 -o PubkeyAuthentication=no -o PreferredAuthentications=password username@sandhole.com.br ...
```

## Automatic reconnection

If you'd like to have persistent tunnels, use a tool like `autossh` to automatically reconnect when disconnected. Note that you might be assigned a new subdomain or port through disconnects, depending on the server configuration.

For a container-based alternative, [check out the Docker Compose example](https://github.com/EpicEric/sandhole/tree/main/docker-compose-example/client) in the repository.
