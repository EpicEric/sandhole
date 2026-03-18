# Benchmarks

This page includes some benchmarks comparing Sandhole and competing solutions.

## Methodology

- **Test service**: [sandhole-benchmark/service](https://github.com/EpicEric/sandhole-benchmark) in release profile, using the given ciphers, running on the same machine as the proxy.
- **Test client**: [sandhole-benchmark/measure](https://github.com/EpicEric/sandhole-benchmark) in release profile, running on the same machine as the proxy.
- **Measurements**: Seven runs in sequence, then average of five best results.

## Results

| aes256-gcm       | sandhole v0.9.2-preview | sish v2.22.1 | Speedup |
| ---------------- | ----------------------- | ------------ | ------- |
| HTTPS GET 50MB   | 111.8ms                 | 109.2ms      | 0.977x  |
| HTTPS GET 100MB  | 195.8ms                 | 178.8ms      | 0.913x  |
| HTTPS POST 50MB  | 125.8ms                 | 137.0ms      | 1.089x  |
| HTTPS POST 100MB | 224.8ms                 | 236.4ms      | 1.052x  |

| chacha20-poly1305 | sandhole v0.9.2-preview | sish v2.22.1 | Speedup |
| ----------------- | ----------------------- | ------------ | ------- |
| HTTPS GET 50MB    | 112.2ms                 | 139.0ms      | 1.239x  |
| HTTPS GET 100MB   | 183.8ms                 | 248.2ms      | 1.350x  |
| HTTPS POST 50MB   | 141.4ms                 | 153.6ms      | 1.086x  |
| HTTPS POST 100MB  | 254.4ms                 | 271.8ms      | 1.068x  |
