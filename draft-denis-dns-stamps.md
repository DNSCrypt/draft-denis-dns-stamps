---
title: "The DNS Stamps Specification"
abbrev: "DNS Stamps"
category: info

docname: draft-denis-dns-stamps-latest
submissiontype: independent
number:
date:
consensus: true
v: 3
area: INT
keyword:
 - DNS
 - DNSCrypt
 - DNS-over-HTTPS
 - DNS-over-TLS
 - DNS-over-QUIC
 - Security
 - Privacy
venue:
  github: jedisct1/draft-denis-dns-stamps
  latest: https://jedisct1.github.io/draft-denis-dns-stamps/draft-denis-dns-stamps.html

author:
 -
    fullname: Frank Denis
    organization: Individual Contributor
    email: fde@00f.net

normative:
  RFC1035:
  RFC2119:
  RFC3986:
  RFC4648:
  RFC5280:
  RFC6125:
  RFC7858:
  RFC8174:
  RFC8484:
  RFC9250:

informative:
  RFC3552:
  RFC8310:
  RFC9230:
  DNSCRYPT:
    title: "DNSCrypt Protocol Specification"
    target: "https://dnscrypt.info/protocol"
    date: 2019
  ODOH:
    title: "Oblivious DNS over HTTPS"
    target: "https://datatracker.ietf.org/doc/draft-pauly-dprive-oblivious-doh/"
    date: 2023

...

--- abstract

This document specifies DNS Stamps, a compact format for encoding the parameters needed to connect to DNS resolvers using various secure protocols. DNS Stamps encode all necessary configuration data including IP addresses, host names, public keys, and protocol-specific parameters into a single URI that can be easily shared and imported by supporting DNS client software. The format supports multiple secure DNS protocols including DNSCrypt, DNS-over-HTTPS (DoH), DNS-over-TLS (DoT), DNS-over-QUIC (DoQ), and Oblivious DoH, as well as relay servers for anonymization.


--- middle

# Introduction

Modern DNS clients support a variety of protocols for secure and private DNS resolution beyond traditional unencrypted DNS {{RFC1035}}. These include DNSCrypt {{DNSCRYPT}}, DNS-over-HTTPS (DoH) {{RFC8484}}, DNS-over-TLS (DoT) {{RFC7858}}, DNS-over-QUIC (DoQ) {{RFC9250}}, and Oblivious DNS-over-HTTPS {{ODOH}}. Each protocol requires different configuration parameters such as IP addresses, host names, paths, port numbers, and cryptographic keys.

Configuring a DNS client to use these secure protocols typically requires users to input multiple parameters correctly, which can be error-prone and creates barriers to adoption. Different client implementations often use incompatible configuration formats, making it difficult to share resolver configurations across applications and platforms.

DNS Stamps address these challenges by encoding all parameters required to connect to a DNS resolver into a single, compact string that uses a URI format. This enables:

- Simple sharing of resolver configurations through copy-paste, QR codes, or URLs
- Consistent configuration format across different client implementations
- Reduced configuration errors through validation of the stamp format
- Support for multiple protocols through a unified format

DNS Stamps have been implemented in numerous DNS client applications and are used by several public DNS resolver operators to publish their server configurations. This document standardizes the DNS Stamps format to ensure interoperability across implementations.

## Notational Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 {{RFC2119}} {{RFC8174}} when, and only when, they appear in all capitals, as shown here.

# Terminology and Definitions

{::boilerplate bcp14-tagged}

This document uses the following terminology and encoding primitives:

`||`
: Denotes concatenation of byte sequences.

`|`
: Denotes the bitwise OR operation.

`len(x)`
: A single byte (unsigned 8-bit integer) representing the length of x in bytes, where x is a byte sequence of maximum length 255.

`vlen(x)`
: Variable length encoding. Equal to len(x) if x is the last element of a set. Otherwise equal to (0x80 | len(x)), indicating more elements follow.

`LP(x)`
: Length-prefixed encoding, defined as len(x) || x.

`VLP(x1, x2, ...xn)`
: Variable-length-prefixed set encoding, defined as vlen(x1) || x1 || vlen(x2) || x2 ... || vlen(xn) || xn.

`[x]`
: Denotes that x is optional.

`base64url(x)`
: The base64url encoding of x as specified in Section 5 of {{RFC4648}}, without padding characters.

Protocol Identifier
: A single byte value that identifies the DNS protocol type encoded in the stamp.

Properties
: A 64-bit little-endian integer encoding informal properties about the DNS resolver.

# DNS Stamps Format Overview

A DNS Stamp is a URI {{RFC3986}} with the following format:

~~~
   "sdns://" base64url(payload)
~~~

Where payload is a protocol-specific byte sequence that always begins with a protocol identifier byte, followed by protocol-specific parameters. The base64url encoding is applied to the entire payload as a single operation, not to individual parameters.

The general structure of the payload is:

~~~
   protocol_id || protocol_specific_data
~~~

## Protocol Identifiers

The following protocol identifiers are defined:

| Value | Protocol |
|-------|----------|
| 0x00  | Plain DNS |
| 0x01  | DNSCrypt |
| 0x02  | DNS-over-HTTPS |
| 0x03  | DNS-over-TLS |
| 0x04  | DNS-over-QUIC |
| 0x05  | Oblivious DoH Target |
| 0x81  | Anonymized DNSCrypt Relay |
| 0x85  | Oblivious DoH Relay |

## Properties Field

Several stamp types include a properties field, which is a 64-bit little-endian integer. The following property flags are defined:

| Bit | Property |
|-----|----------|
| 0   | DNSSEC - The server supports DNSSEC validation |
| 1   | No Logs - The server does not keep query logs |
| 2   | No Filter - The server does not filter or block domains |

All other bits are reserved and MUST be set to zero. Clients MUST ignore unknown property flags.

# Protocol-Specific Stamp Formats

## Plain DNS Stamps

Plain DNS stamps encode parameters for connecting to traditional DNS resolvers:

~~~
   payload = 0x00 || props || LP(addr [:port])
~~~

Where:

- `0x00` is the protocol identifier for plain DNS
- `props` is the properties field (8 bytes, little-endian)
- `addr` is the IP address as a string. IPv6 addresses MUST be enclosed in square brackets (e.g., "[2001:db8::1]"). The port number is optional and defaults to 53.

Example: A plain DNS server at 8.8.8.8 with DNSSEC support would be encoded as:

~~~
   sdns://AAEAAAAAAAAABzguOC44Ljg
~~~

## DNSCrypt Stamps

DNSCrypt stamps encode parameters for DNSCrypt servers:

~~~
   payload = 0x01 || props || LP(addr [:port]) || LP(pk) || 
             LP(providerName)
~~~

Where:

- `0x01` is the protocol identifier for DNSCrypt
- `props` is the properties field (8 bytes, little-endian)
- `addr` is the IP address and optional port. IPv6 addresses MUST be enclosed in square brackets. Default port is 443.
- `pk` is the provider's Ed25519 public key (32 bytes, raw format)
- `providerName` is the DNSCrypt provider name (e.g., "2.dnscrypt-cert.example.com")

## DNS-over-HTTPS Stamps

DoH stamps encode parameters for DNS-over-HTTPS servers:

~~~
   payload = 0x02 || props || LP(addr) || VLP(hash1, ..., hashn) ||
             LP(hostname [:port]) || LP(path) 
             [ || VLP(bootstrap1, ..., bootstrapn) ]
~~~

Where:

- `0x02` is the protocol identifier for DNS-over-HTTPS
- `props` is the properties field (8 bytes, little-endian)
- `addr` is the server IP address (may be empty string)
- `hashi` values are SHA256 digests (32 bytes each) of TBS certificates
- `hostname` is the server hostname for TLS SNI. Default port is 443.
- `path` is the absolute URI path (e.g., "/dns-query")
- `bootstrapi` values are optional IP addresses for resolving hostname

## DNS-over-TLS Stamps

DoT stamps encode parameters for DNS-over-TLS servers:

~~~
   payload = 0x03 || props || LP(addr) || VLP(hash1, ..., hashn) ||
             LP(hostname [:port]) 
             [ || VLP(bootstrap1, ..., bootstrapn) ]
~~~

Where:

- `0x03` is the protocol identifier for DNS-over-TLS
- Parameters have the same meaning as DoH stamps
- Default port is 853

## DNS-over-QUIC Stamps

DoQ stamps encode parameters for DNS-over-QUIC servers:

~~~
   payload = 0x04 || props || LP(addr) || VLP(hash1, ..., hashn) ||
             LP(hostname [:port]) 
             [ || VLP(bootstrap1, ..., bootstrapn) ]
~~~

Where:

- `0x04` is the protocol identifier for DNS-over-QUIC
- Parameters have the same meaning as DoH stamps
- Default port is 853

## Oblivious DoH Target Stamps

ODoH target stamps encode parameters for Oblivious DoH target servers:

~~~
   payload = 0x05 || props || LP(hostname [:port]) || LP(path)
~~~

Where:

- `0x05` is the protocol identifier for Oblivious DoH targets
- `hostname` and `path` have the same meaning as in DoH stamps

## Anonymized DNSCrypt Relay Stamps

DNSCrypt relay stamps encode parameters for anonymization relays:

~~~
   payload = 0x81 || LP(addr [:port])
~~~

Where:

- `0x81` is the protocol identifier for DNSCrypt relays
- `addr` is the relay IP address and port

## Oblivious DoH Relay Stamps

ODoH relay stamps encode parameters for Oblivious DoH relays:

~~~
   payload = 0x85 || props || LP(addr) || VLP(hash1, ..., hashn) ||
             LP(hostname [:port]) || LP(path)
             [ || VLP(bootstrap1, ..., bootstrapn) ]
~~~

Where:

- `0x85` is the protocol identifier for ODoH relays
- Parameters have the same meaning as DoH stamps

# Encoding Examples

This section provides examples of encoding common DNS resolver configurations as stamps.

## Example 1: DNSCrypt Server

Server configuration:
- IP: 185.121.177.177
- Port: 5553
- Provider public key (hex): e801b1d5e2f1e3e34b44d164c1c93a3e92703f99494bb454ed0226d64dc8bf82
- Provider name: 2.dnscrypt-cert.scaleway-fr
- Properties: DNSSEC, no logs, no filter

Encoding steps:
1. Protocol ID: 0x01
2. Properties: 0x07 0x00 0x00 0x00 0x00 0x00 0x00 0x00
3. LP("185.121.177.177:5553"): 0x14 || "185.121.177.177:5553"
4. LP(public key): 0x20 || [32 bytes of public key]
5. LP("2.dnscrypt-cert.scaleway-fr"): 0x1B || "2.dnscrypt-cert.scaleway-fr"

## Example 2: DNS-over-HTTPS Server

Server configuration:
- Hostname: dns.example.com
- Path: /dns-query
- Certificate hash (hex): 1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
- Properties: DNSSEC, no logs

Encoding steps:
1. Protocol ID: 0x02
2. Properties: 0x03 0x00 0x00 0x00 0x00 0x00 0x00 0x00
3. LP(""): 0x00 (empty address)
4. VLP(cert hash): 0x20 || [32 bytes of certificate hash]
5. LP("dns.example.com"): 0x0F || "dns.example.com"
6. LP("/dns-query"): 0x0A || "/dns-query"

# Implementation Considerations

## Stamp Parsing

Implementations parsing DNS stamps MUST:

1. Verify the URI begins with "sdns://"
2. Decode the base64url payload
3. Verify the payload contains at least one byte (protocol identifier)
4. Parse the protocol-specific parameters based on the identifier
5. Validate all length-prefixed fields do not exceed the payload bounds
6. Reject stamps with unknown protocol identifiers
7. Ignore unknown property flags (forward compatibility)

## Stamp Generation

Implementations generating DNS stamps MUST:

1. Use the correct protocol identifier
2. Set only defined property flags
3. Ensure all strings are UTF-8 encoded
4. Apply base64url encoding without padding
5. Validate the total stamp length is reasonable for the use case

## Error Handling

Implementations SHOULD provide clear error messages for common issues:

- Invalid base64url encoding
- Unknown protocol identifier
- Truncated or malformed payload
- Invalid certificate hashes (wrong length)
- Invalid public keys (wrong length or format)

## Internationalization

Hostnames in DNS stamps MUST be represented using their original Unicode form when contained within the stamp payload. Implementations MUST NOT apply Punycode encoding to hostnames before encoding them in stamps. The rationale is that:

1. DNS stamps are not constrained by the ASCII limitations of the DNS protocol
2. Preserving Unicode hostnames improves readability when stamps are decoded
3. Client implementations will apply appropriate encoding when making DNS queries

When establishing TLS connections, implementations MUST convert Unicode hostnames to their ASCII-compatible encoding as required by the underlying protocols.

# Security Considerations

## Stamp Distribution

DNS stamps contain security-critical parameters including cryptographic keys and certificate hashes. The integrity and authenticity of stamps is essential for secure DNS resolution. Stamps obtained from untrusted sources could direct users to malicious resolvers.

Implementations SHOULD:
- Obtain stamps over secure channels (HTTPS)
- Verify stamps against known-good values when possible
- Warn users when importing stamps from untrusted sources
- Validate cryptographic parameters before use

## Certificate Validation

DNS stamps for protocols using TLS (DoH, DoT, DoQ) include SHA256 hashes of certificates in the validation chain. These hashes enable certificate pinning but require updates when certificates are rotated.

Implementations MUST:
- Validate that at least one certificate in the chain matches a provided hash
- Follow standard certificate validation procedures per {{RFC5280}}
- Handle certificate rotation gracefully

Implementations SHOULD:
- Support multiple certificate hashes to enable rotation
- Provide clear error messages for certificate validation failures
- Allow fallback to standard WebPKI validation if explicitly configured

## Privacy Considerations

DNS stamps may contain information that affects user privacy:

- IP addresses reveal the geographic location of resolvers
- Properties flags indicate logging policies
- Bootstrap resolvers may be subject to different privacy policies

Users should be informed about the privacy properties of resolvers encoded in stamps, particularly regarding logging policies and data retention.

## Downgrade Attacks

Clients supporting multiple protocols MUST NOT automatically downgrade from a more secure protocol to a less secure one based on stamp contents. For example, a client should not silently fall back from DoH to plain DNS if both stamps are available.

## Malformed Stamps

Malformed or malicious stamps could potentially cause buffer overflows, infinite loops, or excessive resource consumption. Implementations MUST:

- Validate all length fields before allocation
- Impose reasonable limits on string lengths
- Avoid recursive parsing that could cause stack exhaustion
- Handle base64 decoding errors gracefully

# Operational Considerations

## Stamp Management

Organizations deploying DNS stamps should:

1. Maintain stamps in version control
2. Document the meaning of property flags used
3. Plan for certificate rotation
4. Monitor stamp validity and update as needed
5. Provide both human-readable and stamp formats

## Client Configuration

DNS client implementations using stamps should:

1. Allow users to view decoded stamp contents
2. Support importing stamps from clipboard/files
3. Validate stamps before saving configuration
4. Provide export functionality for sharing
5. Support multiple stamps for failover

## Debugging

For operational debugging, implementations should:

1. Log the decoded contents of stamps
2. Provide tools to decode stamps manually
3. Include stamp details in error messages
4. Support verbose modes showing connection attempts

# IANA Considerations

This document requests IANA to register the "sdns" URI scheme in the "Uniform Resource Identifier (URI) Schemes" registry:

Scheme name: sdns

Status: Provisional

Applications/protocols that use this scheme: DNS client applications using DNS Stamps for configuration

Contact: Frank Denis <fde@00f.net>

Change controller: IETF

References: This document

This document also requests IANA to create a new registry titled "DNS Stamps Protocol Identifiers" with the following initial values:

| Value | Protocol | Reference |
|-------|----------|-----------|
| 0x00  | Plain DNS | This document |
| 0x01  | DNSCrypt | This document |
| 0x02  | DNS-over-HTTPS | This document |
| 0x03  | DNS-over-TLS | This document |
| 0x04  | DNS-over-QUIC | This document |
| 0x05  | Oblivious DoH Target | This document |
| 0x06-0x7F | Unassigned | |
| 0x80  | Reserved for relay protocols | This document |
| 0x81  | Anonymized DNSCrypt Relay | This document |
| 0x82-0x84 | Unassigned | |
| 0x85  | Oblivious DoH Relay | This document |
| 0x86-0xFF | Unassigned | |

Registration policy: Specification Required

This document also requests IANA to create a new registry titled "DNS Stamps Properties Flags" with the following initial values:

| Bit | Property | Reference |
|-----|----------|-----------|
| 0   | DNSSEC | This document |
| 1   | No Logs | This document |
| 2   | No Filter | This document |
| 3-63 | Unassigned | |

Registration policy: Specification Required


--- back

# Implementation Status

{:numbered="false"}

This section records the status of known implementations of the protocol defined by this specification at the time of posting of this Internet-Draft, and is based on a proposal described in RFC 7942.

## dnscrypt-proxy

Organization: Frank Denis

Description: A flexible DNS proxy supporting all DNS stamp types

Maturity: Production

Coverage: Complete

License: ISC

Implementation experience: Excellent

## AdGuard

Organization: AdGuard Software Ltd

Description: Cross-platform ad blocker with DNS protection

Maturity: Production

Coverage: Supports main stamp types (DNSCrypt, DoH, DoT, DoQ)

License: Proprietary

Implementation experience: Good

## Simple DNSCrypt

Organization: Christian Hermann

Description: Simple management tool for dnscrypt-proxy on Windows

Maturity: Production

Coverage: Complete

License: MIT

Implementation experience: Good

# Test Vectors

{:numbered="false"}

This appendix provides test vectors for DNS stamp encoding and decoding.

## Plain DNS Test Vector

Input:
- Protocol: Plain DNS (0x00)
- Properties: DNSSEC (0x01)
- Address: 8.8.8.8

Encoded stamp:
~~~
sdns://AAEAAAAAAAAABzguOC44Ljg
~~~

## DNSCrypt Test Vector

Input:
- Protocol: DNSCrypt (0x01)
- Properties: DNSSEC, No logs, No filter (0x07)
- Address: 176.103.130.130:5443
- Public key (hex): f1b92957c00586a7db2d4c8f1d60c4ec5975c2a3b87bfb3d967c4c5724ad8272
- Provider name: 2.dnscrypt-cert.example

Encoded stamp:
~~~
sdns://AQcAAAAAAAAAEjE3Ni4xMDMuMTMwLjEzMDo1NDQzIPG5KVfABYan2y1Mjx1gxOxZdcKjuHv7PZZ8TFckrYJyFzIuZG5zY3J5cHQtY2VydC5leGFtcGxl
~~~

## DNS-over-HTTPS Test Vector

Input:
- Protocol: DoH (0x02)
- Properties: No logs (0x02)
- Address: (empty)
- Certificate hash (hex): 3b7f6faf59ee948f96b68c79aa2c0589b5c864f2331238f4fe2f8dc7db6ab663
- Hostname: cloudflare-dns.com
- Path: /dns-query

Encoded stamp:
~~~
sdns://AgIAAAAAAAAAAAASY2xvdWRmbGFyZS1kbnMuY29tCi9kbnMtcXVlcnk
~~~

# Change Log

{:numbered="false"}

## Since draft-denis-dns-stamps-00

- Initial version

# Acknowledgments

{:numbered="false"}

The author would like to thank the dnscrypt-proxy community for their feedback and implementation experience with DNS stamps. Special thanks to the developers of the various DNS stamp implementations who have helped refine the format through practical deployment experience.

Thanks also to the developers of secure DNS protocols (DNSCrypt, DoH, DoT, DoQ) whose work made DNS stamps necessary and useful.