> [!WARNING]
> This is unstable and has not been broadly validated against available TACACS+ clients, please use with caution!

# ratchet
Look! It's an Axe! No, a hatchet!

... it's a rusty hatchet!

... it's RATCHET!

## Introduction
This is a TACACS+ server.

It implements PAP, ASCII Authentication, and a basic policy evaluation that seems to support Command Authorization.

It's written in a memory-safe language, and has very few dependencies.

There's a frontend available [here](https://github.com/meltyness/ratchet-pawl), just add glue, middleware, or Nullsoft Installer; [a docker example is available](https://github.com/meltyness/ratchet-cycle).

See https://github.com/meltyness/ratchet-cycle for a neat way to deploy the whole thing.

## Status
This server implements a slim portion of the TACACS+ protocol.

It's very fast and lightweight.

Performance impact hierarchy:
- Credential hashing / crypto
- I/O blocking / contention

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
 RATCHET_USER_CMD_POLICY="./user_cmd_policy_cmd.sh" \
 RATCHET_LONG_POLL="sleep inf"
 RATCHET_CUST_HOSTPORT="[::]:49" \
 ./target/release/ratchet
```
#### Clients and Creds
Where `clients_cmd`, `creds_cmd` correspond to a script that puts a UTF-8 encoded CSV list onto stdout with the following formal-looking line format:

`CLIENTS` := `(` `V4_CIDR_SUBNET|V6_CIDR_SUBNET` `,` `PLAINTEXT KEY` `\n` `)+`

`CREDS` := `(` `COMMALESS_USERNAME` `,` `BCRYPT_PASSWORD_HASH` `\n` `)+`

Don't repeat keys (i.e., specific subnets, specific usernames), sorry.

#### Long polling / update server
`RATCHET_LONG_POLL` is a command that should complete when an upstream server wants to signal to ratchet that clients, creds, etc. have updates. 
- There's also a trivial long-polling protocol involving a serial that can be used to provide a minimal asynchronous update with ratchet as the subscriber to any available changes.

#### Command Authorization Policies
`RATCHET_USER_CMD_POLICY` can, similarly, be used to incorporate a file for Command Authorization processing:

So the `RATCHET_USER_CMD_POLICY` should deliver a file with the following formal-looking file format:

`USER_CMD_POLICY` := 
```
$
a_list_of_users
user1
user2
admin
(
<POLICY_ACE>
<POLICY_ACE>
<POLICY_ACE>
...
)

$
a_different_list_of_users
user3
user4
guest
(
<POLICY_ACE>
<POLICY_ACE>
<POLICY_ACE>
...
)
...
```

So `$` on a line, alone, breaks processing into `subjects` and the `(`, `)` denote the actual set of policy access control entries (ACE).

Each policy ACE for a matched user is processed in-order on a first-matched basis, and in the absence of a match, authorization is default permitted. (see below for an example of default-deny)

Failure modes:
- If users are duplicated in multiple policies, they will inherit the last-defined policy.
- If any policy is not completed, or invalid, then no policy update will take place.
    - To include invalid usernames, misplaced field symbols, unknown field symbols, not enough commas.
- So in short, during updates and initialization, if an invalid policy is provided; then, the last valid policy provided remains in place.

`POLICY_ACE` := `PRECEDENCE`,`POLICY_OUTCOME`,`CRITERIA`,`BLANK/RESERVED`,`TEXT_DATA`

`PRECEDENCE` := An integer `usize`, for when device policies are incorporated.

`POLICY_OUTCOME` := `acc` | `rej`

`CRITERIA` := `<`, `>`, `=` begins with, ends with, and contains; respectively. Use contains sparingly.

`BLANK/RESERVED` := should be blank, ignored, maybe used in the future.

`TEXT_DATA` := An arbitrary string to match against.

##### Policy example
```
$
username
(
10,acc,<,,show
20,rej,<,,reload
20,rej,<,,ping
20,rej,=,,
)
```
**Translation**: The user `username` can run commands starting with `show`, cannot run commands starting with `reload` or `ping`, and finally, may not run any other command. 

Note: Policy is only evaluated in the case where the authorization request contains the `cmd` Authorization argument, when `cmd` is included `cmd-arg`s are also evaluated, so as to reconstruct the original command. 

#### Simplest possible implementation
If you want to do something cheeky like make `RATCHET_READ_CLIENTS="echo '10.10.2.20/32,testing123'` or `RATCHET_READ_CREDS=cat clients_lists.txt` that's fine, I'm easy.

ratchet defines the following defaults:
```rs
        "cat /dev/null",
        "cat /dev/null",
        "sleep inf",
        "echo",
```
corresponding to no clients, no creds, polling that never progresses, and a blank policy, so any environment variables that aren't defined have safe reasonable defaults.

### Testing
In order to run the unit tests you'll need something like. They're far from comprehensive across system configuration.
`sudo apt install libauthen-tacacsplus-perl`

There's future plans to possibly leverage GNS3 so that this system can be tested automatically against arbitrary/proprietary/emulated TACACS clients, but for now some manual testing has it sort of working mostly. 

## Future plans
- [ ] Logging
- [ ] Unauthenticated command authorization policy
- [ ] Device-based command authorization
- [ ] Central command logging based on a policy

### Later
- [ ] CRUD config changes (currently leads to a RwLock order user-count)
- [ ] Benchmarks / Higher-order integration testing
- [ ] Rest of the protocol /
  - [ ] ... CHAP / MSCHAPv2
  - [ ] ... single connection mode
- [ ] Support for complete set of security controls
  - [ ] ... and automated auditing
  - [ ] ... and 8907 future recs
- [ ] fail2ban-like mechanism to protect server from misbehaving clients
- [ ] argonaut / argon for password hashing
- [ ] assess md5 performance / simd?

### Done

- [x] authorization
- [x] command authorization policy definition
- [x] ~~beautiful~~ minimalist front-end
  - [x] Containerized distribution
- [x] complete memory-hardening
  - [x] ... and authenticating against unrecoverable passwords
- [x] assess or implement async to retain maximum performance
- [x] Config interfaces
  - [x] Support for shadowed passwords instead of,... that.
  - [x] Make sure that the CSV escaping makes sense, maybe switch to TSV
- [x] Multi-threaded implementation
  - [x] the ASCII protocol couples too tightly, yikes!
- [x] ASCII Authentication
- [x] Configuration
  - [x] Configurable user list
  - [x] Configurable clients list
  - [x] Configurable port

### Maybe not ...
- [ ] Constructively walk through LLVM opt flag configurations 'rustc passes'
- [ ] Something to meaningfully improve using GNS3 to run tests over this
  - [ ] ... or maybe setup like a dynaMIPS thing some way how

## Kernel Hacking / Optimization
I discovered that when using `perf` to profile `ratchet` that the pipeline was 30% faster, which was,... odd.

After some intense digging, I still don't know for sure, however I did discover that:

- `echo "50" | sudo tee /proc/sys/net/core/busy_poll`
- `echo "50" | sudo tee /proc/sys/net/core/busy_read`

(corresponding to a pretty aggressive polling cycle) yielded *approximately* the same benefit.

😵
