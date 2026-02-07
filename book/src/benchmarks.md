# Benchmarks

This page includes some benchmarks comparing Sandhole and competing solutions.

## Methodology

- **Test service**: [sandhole-benchmark/service](https://github.com/EpicEric/sandhole-benchmark) in release profile, using the given ciphers, running on the same machine as the proxy.
- **Test client**: [sandhole-benchmark/measure](https://github.com/EpicEric/sandhole-benchmark) in release profile, running on the same machine as the proxy.
- **Measurements**: Seven runs in sequence, then average of five best results.

## Results

| aes256-gcm       | sandhole v0.9.0 | sish v2.20.0 | Speedup |
| ---------------- | --------------- | ------------ | ------- |
| HTTPS GET 50MB   | 115.2ms         | 104.8ms      | 0.910x  |
| HTTPS GET 100MB  | 196.8ms         | 179.6ms      | 0.913x  |
| HTTPS POST 50MB  | 120.8ms         | 171.8ms      | 1.422x  |
| HTTPS POST 100MB | 210.6ms         | 260.4ms      | 1.236x  |

| chacha20-poly1305 | sandhole v0.9.0 | sish v2.20.0 | Speedup |
| ----------------- | --------------- | ------------ | ------- |
| HTTPS GET 50MB    | 130.6ms         | 144.8ms      | 1.109x  |
| HTTPS GET 100MB   | 228.4ms         | 245.2ms      | 1.074x  |
| HTTPS POST 50MB   | 144.4ms         | 195.6ms      | 1.355x  |
| HTTPS POST 100MB  | 228.0ms         | 307.4ms      | 1.348x  |
