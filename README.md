# Mission 017 – HTTPS Traffic Analysis

## Overview
This project focuses on practical HTTPS and TLS traffic analysis using Wireshark. The objective was to understand how secure web communication works, identify TLS handshake messages, inspect digital certificates, observe encrypted application data, and compare HTTP with HTTPS.

## Objectives
- Capture HTTPS traffic using Wireshark.
- Identify TLS Client Hello and Server Hello messages.
- Examine TLS 1.3 negotiation and cipher suites.
- Inspect website digital certificates.
- Identify encrypted TLS Application Data.
- Analyze TCP conversations using Follow TCP Stream.
- Capture HTTP GET requests and server responses.
- Compare HTTP and HTTPS communication.

## Tools Used
- Windows
- Wireshark 4.6.9
- Google Chrome
- Wi-Fi network interface

## Practical Activities

### 1. HTTPS Traffic Capture
Captured HTTPS traffic and identified TCP connections using port 443.

### 2. TLS Handshake Analysis
Identified Client Hello and Server Hello messages and examined TLS 1.3 negotiation.

### 3. Certificate Inspection
Inspected the digital certificate for `www.cloudflare.com`, including its subject, issuer, validity period, and SHA-256 fingerprint.

### 4. Encrypted Application Data
Analyzed TLS Application Data records and observed encrypted payloads in Wireshark.

### 5. TCP Follow Stream
Examined the reconstructed TCP conversation and compared the readability of HTTP and HTTPS traffic.

### 6. HTTP Traffic Analysis
Captured ordinary HTTP traffic, identified GET requests, inspected server responses, and examined the communication using Follow TCP Stream.

## Important Wireshark Filters

| Purpose | Display Filter |
|---|---|
| HTTPS TCP traffic | `tcp.port == 443` |
| TLS Client Hello | `tls.handshake.type == 1` |
| TLS Server Hello | `tls.handshake.type == 2` |
| TLS 1.3 Server Hello | `tls.handshake.type == 2 && tls.handshake.extensions.supported_version == 0x0304` |
| TLS Application Data | `tls.record.content_type == 23` |
| HTTP traffic | `http` |
| HTTP requests | `http.request` |
| HTTP responses | `http.response` |
| TCP stream | `tcp.stream eq 7` |

## Key Findings
- Identified a TLS 1.3 connection.
- Observed the `TLS_AES_128_GCM_SHA256` cipher suite.
- Identified the `X25519MLKEM768` key exchange group.
- Inspected the certificate issued by Google Trust Services.
- Observed encrypted TLS Application Data.
- Found that ordinary HTTP request and response information was readable in the capture.
- Understood why HTTPS application payloads are protected from ordinary packet inspection.

## HTTP vs HTTPS
HTTP does not provide TLS encryption, so its application content is generally readable in packet captures. HTTPS uses TLS to protect application data, providing confidentiality and integrity while helping authenticate the server.

## Documentation
Detailed practical documentation, observations, and screenshots are available in:

- `HTTPS-Analysis.md`
- `Screenshots/`

## Skills Practiced
- Network traffic analysis
- Wireshark packet inspection
- TLS 1.3 analysis
- Digital certificate inspection
- HTTP request and response analysis
- TCP stream reconstruction
- Encrypted traffic identification

## Conclusion
This mission provided practical experience in analyzing secure and unsecure web communication. It improved understanding of TLS, digital certificates, encrypted application data, HTTP requests, server responses, and Wireshark investigation techniques.
