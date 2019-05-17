# dns-lookup

This is a simple DNS lookup tool. It connects to a DNS server using TCP and asks for the IPv4 address for a given hostname.
It currently ignores any answers with a type other than `A` (IPv4 address).

## Usage

`dns_lookup DNS_SERVER_ADDR HOSTNAME`

## Building

Just enter `make` on the command line.

## Example

```
$ ./dns_lookup 1.1.1.1 google.com
IP Address: 172.217.14.110
TTL: 164
```
