⚠⚠⚠ This isn't ready for production yet ⚠⚠⚠

# ratchet
Look! It's an Axe! No, a hatchet!

... it's a rusty hatchet!

... it's RATCHET!

## Introduction
This is a TACACS+ server.

It implements PAP and ASCII.

It's written in a memory-safe language, and has very few dependencies.

## Status
This server implements a slim portion of the TACACS+ protocol.

It's very fast and lightweight, with compiler optimization enabled, on a low-end system in a basic configuration, I've seen it service as many as 75,000 requests / sec -- even single-threaded.

## Building / Running / Configuring
There's no external dependencies, so you can just do
`cargo run --release`

### Running / Configuring
But realistically you'll need a script with the following form:
```bash
#!/bin/bash
cargo build --release

# I know Rust is 'memory safe' but let's not go crazy, here.
sudo setcap CAP_NET_BIND_SERVICE=+ep ./target/release/ratchet

RATCHET_READ_CLIENTS="./clients_cmd.sh" \
 RATCHET_READ_CREDS="./creds_cmd.sh" \
 RATCHET_CUST_HOSTPORT="[::]:49" \
 ./target/release/ratchet
```
Where `clients_cmd`, `creds_cmd` correspond to a script that puts a comma-separated list with the following formal-looking format:

`CLIENTS` := `(` `V4_CIDR_SUBNET|V6_CIDR_SUBNET` `,` `PLAINTEXT KEY` `\n` `)+`

`CREDS` := `(` `COMMALESS_USERNAME` `,` `COMMALESS_PLATINTEXT_PASSWORD` `\n` `)+`

Don't repeat keys (i.e., subnets, usernames), sorry.

If you want to do something cheeky like make `RATCHET_READ_CLIENTS="echo '10.10.2.20/32,testing123'` or `RATCHET_READ_CREDS=cat clients_lists.txt` that's fine, I'm easy.

### Testing
In order to run the unit tests you'll need something like. They're far from comprehensive across system configuration.
`sudo apt install libauthen-tacacsplus-perl`

There's future plans to possibly leverage GNS3 so that this system can be tested automatically against arbitrary/proprietary/emulated TACACS clients, but for now some manual testing has it sort of working mostly. 

## Future plans
- [ ] beautiful front-end  
- [ ] Logging
- [ ] Config interfaces
  - [ ] Make sure that the CSV escaping makes sense, maybe switch to TSV
- [ ] assess or implement async to retain maximum performance

### Later
- [ ] Containerized distribution
- [ ] Benchmarks / 
- [ ] Rest of the protocol / MSCHAPv2
- [ ] Support for complete set of security controls
  - [ ] ... and automated auditing
  - [ ] ... and 8907 future recs
  - [ ] ... and authenticating against unrecoverable passwords
- [ ] fail2ban-like mechanism to protect server from misbehaving clients
- [ ] Constructively walk through LLVM opt flag configurations 'rustc passes'
- [ ] CRUD config changes (currently will necessitate brief server relaunch)
- [ ] Something to meaningfully improve using GNS3 to run tests over this
  - [ ] ... or maybe setup like a dynaMIPS thing some way how

### Done

  - [x] Support for shadowed passwords instead of,... that.
- [x] Multi-threaded implementation
  - [x] the ASCII protocol couples too tightly, yikes!
- [x] ASCII Authentication
- [x] Configuration
  - [x] Configurable user list
  - [x] Configurable clients list
  - [x] Configurable port

## Kernel Hacking / Optimization
I discovered that when using `perf` to profile `ratchet` that the pipeline was 30% faster, which was,... odd.

After some intense digging, I still don't know for sure, however I did discover that:

- `echo "50" | sudo tee /proc/sys/net/core/busy_poll`
- `echo "50" | sudo tee /proc/sys/net/core/busy_read`

(corresponding to a pretty aggressive polling cycle) yielded *approximately* the same benefit.

😵
