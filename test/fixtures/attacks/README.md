# Offline technique fixtures

These files are repository-authored metadata and source strings used to exercise
selected analysis signals. They are not malware, copies of malware, or faithful
reconstructions of named incidents, and no package code is executed.

The fixtures cover combinations such as:

1. publishing-account changes and newly added dependencies;
2. rapid publishing plus install-hook, environment, network, and process access;
3. dormancy followed by new dependency metadata;
4. base64 decoding plus dynamic code construction;
5. cross-platform process/network/credential-shaped source patterns;
6. typosquat-like spellings from the curated comparison lists;
7. Python process, network, encoding, filesystem, and system-path patterns; and
8. selected obfuscation and dynamic-loading syntax.

Passing these fixtures means the asserted signals fire on these exact inputs.
It does not measure live-attack recall, general false-positive rate, or whether
vexes would have detected any historical incident before public disclosure.
