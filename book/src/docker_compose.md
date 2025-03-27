# Using Docker Compose

The most straightforward way to have Sandhole up and running is with Docker Compose. Mainly, this takes care of running [Agnos](https://github.com/krtab/agnos) for you, and also daemonizes your application.

For this, you'll first need to install the [Docker Engine](https://docs.docker.com/engine/install/) on your server.

An example configuration is provided in the repository's [docker-compose-example/sandhole](https://github.com/EpicEric/sandhole/tree/main/docker-compose-example/sandhole) directory, using `sandhole.com` as the example domain. Copy the `compose.yml` and `config.toml` files to the desired directory, and adjust them as necessary.

Then, simply run:

```bash
docker compose up -d
```

You should also re-run this command whenever you make changes to your configuration and/or after you update to the latest image (`docker compose pull`). See the [official Docker Compose documentation](https://docs.docker.com/compose/) for more information.

An alternate configuration using [dnsrobocert](https://adferrand.github.io/dnsrobocert/) is available under [docker-compose-example/sandhole-dnsrobocert](https://github.com/EpicEric/sandhole/tree/main/docker-compose-example/sandhole-dnsrobocert).
