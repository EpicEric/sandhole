# Using Docker Compose

The most straightforward way to have Sandhole up and running is with Docker Compose. Mainly, this takes care of running dnsrobocert for you, and daemonizes your application.

For this, you'll first need to install [Docker Engine](https://docs.docker.com/engine/install/) on your server.

An example configuration is provided in the repository's [docker-compose-example](https://github.com/EpicEric/sandhole/tree/main/docker-compose-example) directory, using `server.com` as the example domain and Hetzner as the DNS provider for DNS-01 challenges in `le-config.yml`.

Adjust the fields and CLI flags as appropriate for your use-case. Then, simply run:

```shell
docker compose up -d
```

Then, if you need to restart the service:

```shell
docker compose restart
```

Or stop it entirely:

```shell
docker compose down
```
