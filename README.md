# dns-lookup

This is a simple DNS lookup tool. It connects to a DNS server using TCP and asks for the IPv4 or IPv6 address for a given hostname.
It currently ignores any answers with a type other than `A` (IPv4 address) or `AAAA` (IPv6 address).

## Usage

`dns_lookup [-v6] DNS_SERVER_ADDR HOSTNAME`

## Building

Just enter `make` on the command line.

## Example

```
$ ./dns_lookup 1.1.1.1 google.com
IP Address: 172.217.14.110
TTL: 164
$ ./dns_lookup -v6 1.1.1.1 google.com
IP Address: 2607:f8b0:4007:803::200e
TTL: 95
```
