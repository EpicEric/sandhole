# sandhole

Experimental SSH hole-punching tunnel for exposing HTTP services.

## Status

This is not in a usable state, and mostly serves as an experiment. Contributions are welcome.

If you're looking for a complete solution, check out [sish](https://github.com/antoniomika/sish/) instead.

### TO-DO

Roughly in the order I intend to work on:

- Testing
  - `http.rs`: Mock ConnectionMap and try out different combinations of requests.
  - `ssh.rs`: Test different flows for SSH clients.
  - `certificates.rs`: Test that it can correctly select certificates based on SNI.
    - Maybe mock file system...?
  - `fingerprints.rs`: Test that it can correctly authorize SSH keys.
    - Maybe mock file system...?
  - `lib.rs`: Integration tests...?
- HTTPS redirection
- API-based password authentication
- ACME for certificates
- Admin interface through SSH
- Generic TCP forwarding
- Local port forwarding
- Improve technical debts
- And more
