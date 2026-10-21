# mturoute for macOS

A native macOS port of **mturoute**, the path-MTU discovery tool by Eli Fulkerson
(with fixes by Ivan Pepelnjak). It finds the largest packet that gets through to a
host without fragmentation. In trace mode it also measures that MTU at every hop.

The original Windows tool is built on `IcmpSendEcho()` from `iphlpapi`. This port
replaces that layer with BSD ICMP sockets, as Apple's own `/sbin/ping` does. The
binary-search logic, speed optimizer, options and output are unchanged.

## Build

You need the Xcode Command Line Tools (`xcode-select --install`).

```sh
cd macos
make              # build for this Mac
make universal    # fat binary for Apple Silicon + Intel
sudo make install # copies to /usr/local/bin
```

In VS Code: **Terminal → Run Build Task…** (⇧⌘B).

## Usage

```sh
./mturoute 1.1.1.1          # path MTU to a host
./mturoute -t 1.1.1.1       # traceroute mode: MTU to every hop
./mturoute -t -x 1.1.1.1    # same, with IP addresses redacted
./mturoute -d 1.1.1.1       # debug: show every probe and ICMP result
```

Example:

```
$ ./mturoute 1.1.1.1
* ICMP Fragmentation is not permitted. *
* Speed optimization is enabled. *
* Maximum payload is 10000 bytes. *
+ ICMP payload of 1472 bytes succeeded.
- ICMP payload of 1473 bytes is too big.
Path MTU: 1500 bytes.
```

| Flag | Meaning |
|------|---------|
| `-t` | Traceroute mode |
| `-f` | Allow fragmentation (max ping size, not MTU) |
| `-w ms` | Reply timeout (default 3000) |
| `-r n` | Retries on timeout (default 3) |
| `-i s` | Seconds between probes (default 1, fractions allowed) |
| `-m n` | Maximum payload to test (default 10000) |
| `-H n` | Maximum hops in trace mode (default 30) *(new)* |
| `-d` | Debug output (repeat for more) |
| `-z` / `-p hex` | Random / pattern payload |
| `-s` | Skip speed optimizations |
| `-x` | Redact IP addresses |
| `-v` | Version |

## sudo or not?

- **Without sudo**, it uses an unprivileged `SOCK_DGRAM` ICMP socket, with DF set through `IP_DONTFRAG`. This is the same method `ping -D` uses for normal users.
- **With sudo**, it uses a raw socket and writes the IP header itself (`IP_HDRINCL`) with the DF bit and TTL. This is the same method `ping -D` uses as root.

Both modes should give the same answer. If they don't on your network, trust the
`sudo` result.

## Notes and differences from the Windows version

- IPv4 only. `-6` was never implemented in the original either.
- Packets bigger than your own interface MTU fail locally with `EMSGSIZE` and are
  reported as "too big", so the result includes your first hop.
- With `-f`, macOS caps ICMP datagrams at roughly 8 KB by default
  (`net.inet.raw.maxdgram`). Use `-m` to stay under it.
- MTU probes use TTL 64 (the original used 30).
- In trace mode, "additional device responded" now prints the new device's address.
  The original printed the first one.
- When run with `-d`, it shows the next-hop MTU reported by routers in
  "fragmentation needed" messages.

## Credits and license

- mturoute © Eli Fulkerson, 2005, <http://www.elifulkerson.com>
- Fixes © Ivan Pepelnjak, 2007
- Based on `ping.c` by Francois Gouget, itself based on FreeBSD ping/traceroute

The original source was released under these terms: *"All the applications are free
(BSD, GNU, or even no license) and come with the source. Don't hesitate to modify
them, tweak them, enhance them."* Eli applied the same terms to his modifications,
and this port keeps them.
