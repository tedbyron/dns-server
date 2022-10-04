# dns-thingy

```sh
nc -u -l 1234 > query_packet
dig +retry=0 -p 1234 @127.0.0.1 +noedns google.com
nc -u 8.8.8.8 53 < query_packet > response_packet
```
