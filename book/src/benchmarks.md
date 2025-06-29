# Benchmarks

This page includes some benchmarks comparing Sandhole and competing solutions.

## Methodology

- **Test service**: [sandhole-benchmark/service](https://github.com/EpicEric/sandhole-benchmark) in release profile, using AES-256-GCM.
- **Test client**: [sandhole-benchmark/measure](https://github.com/EpicEric/sandhole-benchmark) in release profile.
- **Service-to-proxy latency**:

```
--- sandhole.com.br ping statistics ---
30 packets transmitted, 30 received, 0% packet loss, time 29131ms
rtt min/avg/max/mdev = 141.265/144.842/150.421/2.243 ms
```

- **Client-to-proxy latency**: Same as above.
- **Measurements**: Two cold runs, then average + standard deviation of five results.

## Results

|                 | sandhole v0.6.0   | sish v2.19.0         | Speedup |
| --------------- | ----------------- | -------------------- | ------- |
| HTTPS GET 50MB  | 9s 351ms ± 193ms  | 10s 500ms ± 1s 110ms | 1.123x  |
| HTTPS GET 100MB | 17s 264ms ± 342ms | 13s 837ms ± 1s 512ms | 0.802x  |
| HTTPS POST 50MB | 11s 252ms ± 180ms | 12s 677ms ± 305ms    | 1.126x  |

- At smaller transfer sizes, Sandhole is faster.
- Latency is much more consistent in Sandhole.
