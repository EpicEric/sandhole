# Introduction

Welcome to the **Sandhole book**. This is a work-in-progress guide on how to install, maintain, and use an instance of Sandhole.

## About the project

[Sandhole](https://github.com/EpicEric/sandhole) is an experimental reverse proxy that uses SSH's built-in reverse port forwarding functionality, in order to allow services to expose themselves to the Internet. This is especially useful as a way for servers behind NAT to expose themselves, but you may also want this for:

- Quickly prototyping websites and TCP services, and sharing them with others.
- Handling a multi-tenant network with several websites under the same domain.
- Hosting a dual-stack HTTP+SSH service (via ProxyJump), such as Git instances.
- And possibly more!
