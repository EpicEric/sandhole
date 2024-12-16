# Introduction

Welcome to the **Sandhole book**. This is a guide on how to install, configure, and use an instance of Sandhole.

## About the project

[Sandhole](https://github.com/EpicEric/sandhole) is an unconventional reverse proxy that uses SSH's built-in reverse port forwarding functionality, in order to allow services to expose themselves to the Internet. This is especially useful for services behind NAT, but you may also want this for:

- Quickly prototyping websites, APIs, and TCP services, and sharing them with others.
- Handling a multi-tenant network with several websites under the same domain.
- Hosting a dual-stack HTTP+SSH service (via ProxyJump), such as a Git instance.
- Exposing endpoints or ports on IoT devices, games, or other applications.
- Using the tunnel for peer-to-peer connections, or even as a basic VPN.
- And possibly more!
