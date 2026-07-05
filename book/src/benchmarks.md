# Benchmarks

This page includes some benchmarks comparing Sandhole and competing solutions.

## Methodology

- **Test service**: [sandhole-benchmark/service](https://github.com/EpicEric/sandhole-benchmark) in release profile, using the given ciphers, running on the same machine as the proxy.
- **Test client**: [sandhole-benchmark/measure](https://github.com/EpicEric/sandhole-benchmark) in release profile, running on the same machine as the proxy.
- **Measurements**: Seven runs in sequence, then average of five best results.

## Results

| aes256-gcm       | sandhole v0.10.2 | sish v2.23.0 | Speedup |
| ---------------- | ---------------- | ------------ | ------- |
| HTTPS GET 50MB   | 114.6ms          | 114.0ms      | 0.995x  |
| HTTPS GET 100MB  | 194.6ms          | 190.4ms      | 0.978x  |
| HTTPS POST 50MB  | 127.0ms          | 133.0ms      | 1.047x  |
| HTTPS POST 100MB | 214.2ms          | 233.6ms      | 1.091x  |

| chacha20-poly1305 | sandhole v0.10.2 | sish v2.23.0 | Speedup |
| ----------------- | ---------------- | ------------ | ------- |
| HTTPS GET 50MB    | 110.0ms          | 144.2ms      | 1.311x  |
| HTTPS GET 100MB   | 189.2ms          | 248.0ms      | 1.311x  |
| HTTPS POST 50MB   | 145.6ms          | 159.0ms      | 1.092x  |
| HTTPS POST 100MB  | 235.6ms          | 274.6ms      | 1.166x  |
