# netsniff

**netsniff** is a lightweight, command-line network packet capture and inspection tool written in C and built on top of **libpcap**.  
It captures traffic from live network interfaces or PCAP files, decodes common protocols, and presents either per-packet output or aggregated statistics.

---

## Features

- Live packet capture from network interfaces
- Offline analysis of PCAP files
- Ethernet frame decoding
- IPv4 and IPv6 packet parsing
- TCP, UDP, ICMP, and ICMPv6 support
- Optional periodic statistics reporting
- BPF filter support
- Automatic default interface selection
- Clean, readable CLI output

---

## Building

### Requirements

- A Unix-like system
- `libpcap` and development headers
- C compiler (Clang or GCC)
- CMake ≥ 3.16

## Build


```sh
git clone https://github.com/<your-username>/netsniff.git
cd netsniff

cmake --preset dev
cmake --build --preset dev
```

For a release build:

```sh
cmake --preset release
cmake --build --preset release
```

The resulting binary will be named `netsniff`.

---

## Usage

> Live capture generally requires elevated privileges (e.g. `sudo`) or appropriate capabilities.

### Basic capture

```sh
sudo netsniff
```

If no interface is specified, netsniff will automatically select a suitable default interface.

### Specify interface

```sh
sudo netsniff --iface en0
```

### Read from a PCAP file

```sh
netsniff --read capture.pcap
```

### List available interfaces

```sh
netsniff --list-ifaces
```

### Limit packet count

```sh
sudo netsniff --count 100
```

### Capture a single packet
```sh
sudo netsniff --once
```

### Apply a BPF filter
```sh
sudo netsniff --filter "tcp port 443"
```

### Statistics mode

```sh
sudo netsniff --stats
```

With a custom reporting interval:

```sh
sudo netsniff --stats --interval 5
```

---

## Example Output

### Per-packet mode

~~~text
192.168.1.10:51234 -> 142.250.179.78:443 TCP (https)
192.168.1.10:5353 -> 224.0.0.251:5353 UDP (dns)
fe80::1c2b:ff:fe3a:91e2 -> ff02::1 ICMPv6
~~~

### Statistics mode

~~~text
rate=285 packets/s total=285 tcp=236 udp=23 icmp=18 icmpv6=1 other=7 |
dst 53=3 80=0 443=10 other=28
~~~

---

## Design Overview

The codebase is structured as a small pipeline:

~~~text
CLI / Configuration
        ↓
Packet Capture (libpcap)
        ↓
Ethernet Decode
        ↓
IPv4 / IPv6 Decode
        ↓
L4 Decode (TCP / UDP)
        ↓
Output / Statistics
~~~

### Key design choices

- Strict bounds checking before all header access
- Explicit endianness handling
- Layered decoding (L2 → L3 → L4)
- Clear separation of concerns between modules
- Fail-fast on malformed packets, graceful handling otherwise

Only Ethernet (`DLT_EN10MB`) is currently supported.


