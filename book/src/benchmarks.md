# Benchmarks

This page includes some benchmarks comparing Sandhole and competing solutions.

## Methodology

- Test service: [sandhole-benchmark](https://github.com/EpicEric/sandhole-benchmark) in dev profile.
- Test client: Postman v11.50.5
- Proxy server specs:
  - 2 vCPU (AMD EPYC 7002 series)
  - 2 GB RAM
- Service-to-proxy latency:

```
--- sandhole.com.br ping statistics ---
30 packets transmitted, 30 received, 0% packet loss, time 29092ms
rtt min/avg/max/mdev = 140.542/142.646/146.181/1.102 ms
```

- Client-to-proxy latency: Same as above.
- Times measured through the Postman client, by taking 6 measurements, discarding the first result, and taking an average of the remaining five.

## Results

|                 | sandhole 4dfc112 | sish v2.19.0 | Speedup |
| --------------- | ---------------- | ------------ | ------- |
| HTTPS GET 10MB  | 3.072s           | 2.655s       | 0.864x  |
| HTTPS GET 50MB  | 10.766s          | 8.732s       | 0.811x  |
| HTTPS POST 10MB | 3.144s           | 4.746s       | 1.510x  |
| HTTPS POST 50MB | 10.582s          | 14.902s      | 1.408x  |
