# Changelog

## Unreleased

- Update russh to 0.54.1.

## 0.8.0

### Added

- Add `--load-balancing-algorithm` CLI flag.
- Add `--random-subdomain-value` CLI flag.
- Add `--requested-subdomain-filter-profanities` CLI flag.
- Add `--ssh-keepalive-interval` and `--ssh-keepalive-max` CLI flags.
- Add current connection count to admin interface for SSH/SNI/TCP/alias.
- Add feature flags for login, rustrict, ACME, and Prometheus.

### Changed

- **BREAKING**: `--requested-domain-filter-profanities` no longer filters subdomains (use `--requested-subdomain-filter-profanities` instead).
- Update dependencies.

### Fixed

- Don't show "PTY allocation request failed" messages.
- Return error to forwarding service if Sandhole fails to bind a TCP port.

## 0.7.0 (2025-07-09)

### Added

- Add support for admin-only aliases.
- Add Prometheus support via admin-only alias `prometheus.sandhole:10`.
- Add `--disable-prometheus` CLI flag.

### Changed

- **BREAKING**: Disable aliasing on port 10.

## 0.6.1 (2025-07-05)

### Changed

- Use `tracing` for HTTP logs.

### Fixed

- Move TCP connections to spawned tasks.
- Fix TCP logs.

## 0.6.0 (2025-06-29)

### Changed

- **BREAKING**: Always disconnect on invalid SSH exec commands.
- **BREAKING**: Use `--idle-connection-timeout` for dangling TLS connections instead of `--tcp-connection-timeout`.
- Make performance improvements.
- Replace `anyhow` with `color-eyre`.

### Fixed

- Defer HTTP logs to when body is fully transmitted.

## 0.5.4 (2025-06-08)

### Added

- Add `--rate-limit-per-user` CLI flag.

### Changed

- Update Docker base image.
- Update dependencies.
- Replace `env_logger` with `tracing`.
- Refactor `peek_sni_and_alpn()`.

### Fixed

- Improvements to admin interface shutdown.
- Fix SNI proxies not being removed on disconnect.
- Timeout waiting for TLS connection.

## 0.5.3 (2025-05-24)

### Added

- Add `--disable-https` CLI flag.
- Add keepalive interval for SSH connections.

### Changed

- Change default `--buffer-size` to 32KB.
- Match SSH's maximum packet size to `--buffer-size`.

## 0.5.2 (2025-04-27)

### Added

- Add `--buffer-size` CLI flag.

### Changed

- Change `rustls-platform-verifier` dependency for `webpki-roots`.
- Update dependencies.

## 0.5.1 (2025-03-31)

### Added

- Add `sni-proxy` option for remote forwarding connections.
- Add `--disable-sni` CLI flag.

### Fixed

- Fix logging to remote forwarding sessions.

## 0.5.0 (2025-03-23)

### Added

- Add `http2` option for remote forwarding connections.

### Fixed

- Fix interpreting messages from all data channels.
- Improve logic for SSH exec commands.
- Flush messages to data channel when closing connection.
- Show cursor in admin interface only on shutdown.

### Changed

- **BREAKING**: Shutdown when trying to open admin interface in invalid context.
- Update dependencies.
- Bump MSRV to 1.85.0.
- Use `reqwest` for the login API.

## 0.4.0 (2025-02-11)

### Fixed

- Further fixes to HTTPS connections lock-ups.

### Changed

- **BREAKING**: Make `--http-request-timeout` optional by default.

## 0.3.2 (2025-01-12)

### Added

- Add User-Agent to login API requests.
- Add `force-https` option for remote forwarding connections.
- Add `ip-allowlist`/`ip-blocklist` options for remote forwarding connections.
- Add telemetry for SSH/TCP/alias connections.

### Fixed

- Fix HTTP aliasing not working.
- Fix HTTPS connections occasionally locking up.

### Changed

- Error early on missing/blocked HTTP alias for `channel_open_direct_tcpip`.
- Return "unknown alias" error messages when failing any pre-conditions.
- Change default value of `--http-request-timeout` to 30s.

## 0.3.1 (2024-12-31)

### Added

- Add key algorithm to user details in the admin interface.
- Add `--disable-http` CLI flag.
- Add `--disable-tcp` CLI flag.
- Add `--random-subdomain-filter-profanities` CLI flag.
- Add `--requested-domain-filter-profanities` CLI flag.
- Add `--ip-allowlist` CLI flag.
- Add `--ip-blocklist` CLI flag.

### Changed

- Separate TCP and alias logic.
- Remove inaccesible tabs from admin interface when using one or more of the `--disable-*` flags.
- Set nodelay for TCP streams.
- Don't duplicate fingerprints logic.

## 0.3.0 (2024-12-28)

### Added

- Add user detail popups to admin interface.
- Add functionality to remove users via the admin interface.
- Add CLI to integration tests.
- Add mechanism to disconnect unproxied unauthed users.
- Add `tcp-alias` option for remote forwarding connections.
- Add `--disable-aliasing` CLI flag.
- Add `--unproxied-connection-timeout` CLI flag.
- Add `--random-subdomain-length` CLI flag.

### Fixed

- **BREAKING:** Panic if required directories are missing.
- Prevent memory leak if a session hasn't been opened.
- Improve support for HTTP aliases.
- Use `proxy_handler` for HTTP local forwardings.
- Better handling of `exec_request` commands.

### Changed

- **BREAKING**: Downgrade HTTP hosts to aliases when passing `allowed-fingerprints`.
- Bump MSRV to 1.82.0.
- Consolidate configurations.
- Warn when one of multiple parsings fail.

## 0.2.1 (2024-12-22)

### Added

- Add Sandhole version to admin interface.
- Add signal handling for shutdown.

### Fixed

- Fix SSH authentication log always showing "no authentication".

### Changed

- Minor improvements to admin interface.

## 0.2.0 (2024-12-20)

### Added

- **BREAKING**: Add `remote_address` field to API login request.
- Add user forwarding quotas via the `--quota-per-user` option.
- Add `--connect-ssh-on-https-port` option.
- Add user IDs to admin interface.

### Fixed

- Better handling of initial value and windowing for telemetry counters.
- Improve random addressing to avoid most collisions.

### Changed

- **BREAKING**: Rename `--allow-provided-subdomains` to `--allow-requested-subdomains`.
- Bump MSRV to 1.81.0.
- Change `--random-subdomain-seed=fingerprint` to also take user into account.
- Modify exports to live within `lib.rs`.
- Update `russh` dependency to version `0.49.2`.
- Update `sysinfo` dependency to version `0.33.0`.

## 0.1.4 (2024-12-03)

### Changed

- Update `russh` dependency to version `0.47.0-beta.4` in order to be published to Crates.io.

## 0.1.3 (2024-11-30)

### Added

- Add system info to admin interface.

### Fixed

- Fix leak with SSH connections.

### Changed

- Revamp admin interface.
- Improve counter measurements.
- Improve placeholders in CLI.
- Use DroppableHandle in more places.

## 0.1.2 (2024-11-27)

### Added

- Add logging for ACME certificates.
- Basic documentation for docs.rs.

### Changed

- Improve logging when using `--load-balance=replace`.
- Make fingerprint-checking consistent.
- Better logging/admin interface with canonical IPs.
- Remove some unecessary allocations.
- Decrease size of Docker images.

## 0.1.1 (2024-11-26)

### Fixed

- Fix fingerprint verification for non-alias flows.

### Changed

- Remove dependency on `reqwest`.

## 0.1.0 (2024-11-25)

Initial release.
