# TODO

Future improvements identified during a review of the egress-IP discovery logic.

- [x] **Use cautious terminology for multiple results.** Do not label every pair of
  different observed egress IPs as "load balancing." First report "multiple egress
  mappings observed," since destination-dependent/symmetric NAT, proxy/VPN policy,
  and service-specific routing can also produce this result.

- [x] **Correct the STUN fallback.** `OTHER-ADDRESS` identifies an alternate STUN
  server, not the client's mapped public address. Only accept `XOR-MAPPED-ADDRESS`
  (or the legacy `MAPPED-ADDRESS` where appropriate) as an observed exit address.

- [x] **Validate HTTP responses before extracting an IP.** Require a successful
  HTTP status code and bound the response body. Otherwise captive portals, proxy
  error pages, and arbitrary HTML containing an IP can become false positives.

- [x] **Make confidence inputs explicit.** Display successful probes, attempted
  probes, per-protocol successes, and agreement separately. Avoid a high-sounding
  confidence label when the overall success rate is low.

- [x] **Add a longer and repeatable sampling mode.** The current small sample
  count may miss time-based or flow-hash-based egress changes. Add configurable
  sample count, interval, duration, and a machine-readable results export so runs
  can be compared.
