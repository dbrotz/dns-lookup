# dns-lookup

This is a simple DNS lookup tool. It connects to a DNS server using TCP and asks for the IPv4 or IPv6 address for a given hostname.
It handles `A` (IPv4 address), `AAAA` (IPv6 address), and `CNAME` (canonical name) records. When it receives a `CNAME` record,
it will inform the user that it is switching to the provided canonical name and attempt to find a matching address record later in the same response.
If one is not found, it will attempt another query using the new name.

## Usage

`dns_lookup [-v6] DNS_SERVER_ADDR HOSTNAME`

`DNS_SERVER_ADDR` is the IPv4 address of the DNS server to query.

`HOSTNAME` is the hostname whose IP address is to be looked up.

By default, the IPv4 address is looked up. If the `-v6` option is used, then the IPv6 address is looked up instead.

## Building

Just enter `make` on the command line.

## Example

```
$ ./dns_lookup 1.1.1.1 google.com
IP Address: 172.217.14.110
TTL: 164
Authoritative: no
$ ./dns_lookup -v6 1.1.1.1 google.com
IP Address: 2607:f8b0:4007:803::200e
TTL: 95
Authoritative: no
```
