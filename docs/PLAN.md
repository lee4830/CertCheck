# SSL Certificate Checker Implementation Plan

Goal: provide a buildable and runnable Windows 11 x64 portable GUI and source archive.
Architecture: Core handles input, TLS capture, Windows validation and serialization; Gui provides WinForms; Tests is a dependency-light executable integration suite.
Spec: DESIGN.md and the user's continuation request.

1. Rules.cs: test normalization, IDN, IPv6, invalid inputs, exact expiry and fixed KST first; implement and run Tests.
2. Probe.cs/Models.cs: add local real TLS server tests first for expired/untrusted/mismatched cert retention, timeout/cancellation and exact chain collection. Implement synchronous BC handshake on a worker thread with socket-closing cancellation; Windows chain build separately.
3. Storage.cs: test deduplication, cap, corruption handling and PEM/JSON preservation; implement atomic local history.
4. Gui: Korean accessible native controls, resizable tabs for overview/details/wire chain/OS chain/DNS/history, copy/export and cancellation; verify live UI and backend integration.
5. Publish self-contained win-x64 single file, run the published app, package clean source with build/test commands, dependency license, verification report and checksums.

Review focus: expired certificates must remain available; SNI must not change the TCP host; OS trust errors must not claim success; cancellation must close sockets; old results must not be exported under a new target after failure.
