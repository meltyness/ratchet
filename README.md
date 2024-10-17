⚠⚠⚠ This isn't ready for production yet ⚠⚠⚠

# ratchet
Look! It's an Axe! No, a hatchet!

... it's a rusty hatchet!

... it's RATCHET!

## Introduction
This is a TACACS+ server.

It implements (part of) PAP.

It's written in a memory-safe language, and has very few dependencies.

## Status
This server implements a slim portion of the TACACS+ protocol.

It's very fast and lightweight, with compiler optimization enabled, on a low-end system in a basic configuration, it's potentially capable of servicing as many as 32,000 requests / sec -- even single-threaded.

## Future plans
- [ ] Configuration
  - [x] Configurable user list
  - [ ] Configurable clients list
  - [ ] Configurable port
- [ ] Logging


Later
- [ ] beautiful front-end
- [ ] Benchmarks / Multi-threaded implementation
- [ ] Rest of the protocol / MSCHAPv2
- [ ] Support for complete set of security controls
  - [ ] ... and automated auditing
  - [ ] ... and 8907 future recs
- [ ] fail2ban-like mechanism to protect server from misbehaving clients
- [ ] Constructively walk through LLVM opt flag configurations 'rustc passes'
- [ ] CRUD config changes (currently will necessitate brief server relaunch)

## Kernel Hacking / Optimization
I discovered that when using `perf` to profile `ratchet` that the pipeline was 30% faster, which was,... odd.

After some intense digging, I still don't know for sure, however I did discover that:
`echo "50" | sudo tee /proc/sys/net/core/busy_poll`
`echo "50" | sudo tee /proc/sys/net/core/busy_read`

(corresponding to a pretty aggressive polling cycle) yielded *approximately* the same benefit.

😵
