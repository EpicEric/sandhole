# Changelog

## Unreleased

### Fixed

- Better handling of initial value and windowing for telemetry counters.

### Changed

- Add `remote_address` field to API login request.
- Bump MSRV to 1.79.0.
- Update `russh` dependency to version `0.50.0-beta.1`.
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
