# Benchmarks

This page includes some benchmarks comparing Sandhole and competing solutions.

## Methodology

- **Test service**: [sandhole-benchmark/service](https://github.com/EpicEric/sandhole-benchmark) in dev profile.
- **Test client**: [sandhole-benchmark/measure](https://github.com/EpicEric/sandhole-benchmark) in dev profile.
- **Service-to-proxy latency**:

```
--- sandhole.com.br ping statistics ---
30 packets transmitted, 30 received, 0% packet loss, time 29092ms
rtt min/avg/max/mdev = 140.542/142.646/146.181/1.102 ms
```

- **Client-to-proxy latency**: Same as above.
- **Measurements**: Average of five results, discarding outliers.

## Results

|                                | sandhole d6fc28d | sish v2.19.0 | Speedup |
| ------------------------------ | ---------------- | ------------ | ------- |
| HTTPS GET 10MB                 | 3.853s           | 2.697s       | 0.700x  |
| HTTPS GET 10MB x5 concurrency  | 11.245s          | 10.041s      | 0.893x  |
| HTTPS GET 50MB                 | 11.832s          | 8.790s       | 0.743x  |
| HTTPS POST 10MB                | 3.539s           | 4.811s       | 1.359x  |
| HTTPS POST 10MB x5 concurrency | 9.748s           | 11.556s      | 1.186x  |
| HTTPS POST 50MB                | 11.700s          | 14.400s      | 1.231x  |
