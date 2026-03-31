# Attack Simulations

These fixtures reconstruct real-world supply chain attacks as test data.
No actual malicious code is executed — these are JSON metadata and JS source
strings fed directly into the analysis pipeline.

## Attacks Simulated

1. **axios-rat** — March 2026: Maintainer account hijacked, malicious version
   published with hidden dependency `plain-crypto-js` that deploys RAT

2. **shai-hulud** — September 2025: Self-replicating worm injected into chalk,
   debug, ansi-styles via phished maintainer credentials

3. **event-stream** — November 2018: New maintainer added `flatmap-stream`
   dependency containing encoded payload targeting bitcoin wallets

4. **ua-parser-js** — October 2021: Maintainer hijacked, cryptominer and
   password stealer injected into postinstall

5. **colors-faker** — January 2022: Original maintainer deliberately broke
   packages, infinite loop in colors, all data deleted from faker

6. **typosquat-generic** — Common attack: package with name similar to
   popular package, brand new, single maintainer, contains payload
