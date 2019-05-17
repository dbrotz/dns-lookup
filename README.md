# dns-lookup

This is a simple DNS lookup tool. It connects to a DNS server using TCP and asks for the IPv4 or IPv6 address for a given hostname.
It handles `A` (IPv4 address), `AAAA` (IPv6 address), and `CNAME` (canonical name) records. When it receives a CNAME record,
it will inform the user that it is switching to the provided canonical name and attempt to find a matching address record later in the same response.
If one is not found, the user currently has to manually perform another query using the new name.

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
