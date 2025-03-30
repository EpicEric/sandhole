# Introduction

![The Sandhole logo, with Ferris partially inside a sandhole and the name "Sandhole" written in cursive beside them.](./logo.png)

Welcome to the **Sandhole book**. This is a guide on how to install, configure, and use an instance of Sandhole.

## About the project

[Sandhole](https://github.com/EpicEric/sandhole) is an unconventional reverse proxy which uses the built-in reverse port forwarding from SSH, allowing services to expose themselves to the Internet with minimal configuration. This is especially useful for services behind NAT, but you may also use Sandhole for:

- Quickly prototyping websites, APIs, and TCP services, and sharing them with others.
- Exposing endpoints or ports on IoT devices, game servers, and other applications.
- Hosting a dual-stack HTTP+SSH service (via ProxyJump), such as a Git instance.
- Handling a multi-tenant network with several websites under the same domain.
- Using the tunnel for ad hoc peer-to-peer connections, or [even as a basic VPN](./local_forwarding.md).
- And possibly more!
