# Changelog

## 0.1.4 (2024-12-03)

### Changed

- Update `russh` dependency to version `0.47.0-beta.4` in order to be published to Crates.io

## 0.1.3 (2024-11-30)

### Added

- Add system info to admin interface

### Fixed

- Fix leak with SSH connections

### Changed

- Revamp admin interface
- Improve counter measurements
- Improve placeholders in CLI
- Use DroppableHandle in more places

## 0.1.2 (2024-11-27)

### Added

- Add logging for ACME certificates
- Basic documentation for docs.rs

### Changed

- Improve logging when using `--load-balance=replace`
- Make fingerprint-checking consistent
- Better logging/admin interface with canonical IPs
- Remove some unecessary allocations
- Decrease size of Docker images

## 0.1.1 (2024-11-26)

### Fixed

- Fix fingerprint verification for non-alias flows

### Changed

- Remove dependency on `reqwest`

## 0.1.0 (2024-11-25)

Initial release.
