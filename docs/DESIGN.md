# SSL Certificate Checker — implementation design

The user's implementation request and referenced GUI proposal are the specification. Build a Korean Windows 11 x64 portable desktop app, with sources and explicit verification limits. Implementation choices are the builder's responsibility under that request.

Use .NET 10 WinForms, self-contained single-file publication. Use Bouncy Castle TLS 1.2/1.3 to retain the exact peer Certificate message in the same connection; Windows X509Chain separately builds and validates using local trust and received intermediates. Do not relabel an OS chain as the wire chain. No HTTP or application payload is sent. Validation errors do not discard certificates; TLS protocol errors can still prevent retrieval.

Inputs: host/IP, port, optional independent DNS SNI/validation identity, SNI toggle, timeout, optional online revocation. An IP default sends no SNI. With SNI disabled, hostname validation still uses the configured identity. Show DNS candidates and actual remote endpoint. KST is fixed UTC+09; D-day is full remaining 24-hour periods, with exact expiry checked first. Show SAN, dates, issuer, subject, signature, SHA-256 and chain statuses. Copy report, JSON/PEM/CER export, and local 50-entry history with clear/load support.

Alternatives: native SslStream is simpler but exposes the OS-built chain rather than guaranteeing the sent chain; a bundled OpenSSL subprocess adds binary distribution and process parsing. Managed Bouncy Castle keeps the exact chain and fits single-file delivery.

Default revocation is not checked and is labeled as such. AIA downloads are disabled; OS cache/store may still complete a missing intermediate. Explicit online revocation can make network requests. No custom trust roots are installed. No installer, admin rights or Python required; unsigned EXE may show Windows reputation prompts. x64 is the initial target; no ARM64 validation.
