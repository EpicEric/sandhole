# Technical overview

This page goes over the technical details about Sandhole's inner workings. Feel free to skip this page if you are only interested in using Sandhole.

## Secure Shell

[SSH](https://en.wikipedia.org/wiki/Secure_Shell) is a powerful protocol, with built-in features such as encryption and authentication. It's widely used to access remote servers, in order to get access to a shell or transfer Git repositories, for example.

One of its less known features is the ability to forward ports between the client and the server. With an OpenSSH server, it's possible to do:

- Local port forwarding: Accessing a port from the server, as if it were a local service on your machine.
- Remote port forwarding: Exposing a port from a local service to the server, as if it were a remote service running on the server.

See [this post on SSH tunneling](https://web.archive.org/web/20250221173009/https://goteleport.com/blog/ssh-tunneling-explained/) for more information.

Sandhole is capable of handling both, albeit in a different way than a regular OpenSSH server.

## Reverse proxy

A reverse proxy is an intermediary server that receives and forwards requests to a backend service. They are commonly used to secure traffic, or expose servers behind a firewall/private network.

Sandhole is itself a reverse proxy. It leverages SSH for authentication and tunneling of services, while transparently handling client requests.

![A diagram displaying Sandhole's usage as a reverse proxy. It's deployed to a public server, where a local service connects to its SSH port. A remote service in a private server also connects to the SSH port over the Internet. Meanwhile, a client's web browser connects to the HTTPS port of Sandhole over the Internet.](./how_it_works.svg)

As such, it's possible to expose services publicly without needing a VPN, even when the private server is behind NAT or firewalls.

## Example flow

Let's say that client A wishes to expose a local service, running on port 8080, to the Internet.

![A diagram showing a connection to Sandhole's HTTP proxy in six steps.](./example_flow.svg)

1. Client A connects to a Sandhole instance while requesting a remote port forwarding:

```bash
ssh -p 2222 -R mytunnel:80:localhost:8080 sandhole.com.br
```

2. Sandhole handles the forwarding request and starts proxying requests from `http://mytunnel.sandhole.com.br` to client A's port 8080.

3. Client B accesses `http://mytunnel.sandhole.com.br` through a web browser.

4. Sandhole opens a tunneling channel over SSH to client A, simulating a TCP stream containing client B's request.

5. Client A's HTTP server replies over the SSH channel.

6. Sandhole forwards the reply to client B.

To client A, requests arrive normally at the socket, despite only having an outbound SSH connection; to client B, Sandhole transparently acts as if it were the service itself.

Here's the same flux in a sequence diagram:

```mermaid
sequenceDiagram
  participant SC as SSH client
  participant SS as SSH server
  participant M as Connection map
  participant HS as HTTP server
  participant HC as Web client

  Note over SC, M: Tunnel setup
  SC ->> SS: SSH connection + tcpip_forward
  SS ->> SS: Validate login
  SS ->> M: Register tunnel handler
  Note over SC, HC: Traffic routing
  HC ->>+ HS: HTTP request to assigned domain
  HS ->> M: Look up tunnel for domain
  HS ->>+ SS: Forward request via tunnel
  SS ->>+ SC: Relay to local service
  SC -->>- SS: Response from local service
  SS -->>- HS: Forward response
  HS -->>- HC: Return HTTP response
```
