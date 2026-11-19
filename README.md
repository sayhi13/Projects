# Low-Level & Security Projects

A collection of low-level tools, hardware/NFC firmware, and network experiments built for hands-on learning, lab testing, and protocol exploration.

---

## Repositories

| Project | Focus & Overview | Notes |
| :--- | :--- | :--- |
| **[arp-spoofer](https://github.com/sayhi13/Projects/tree/main/arp-spoofer)** | Custom penetration-testing utility for observing how routers handle ARP spoofing in lab/authorized environments. | MITM or DoS |
| **[asm-encrypter](https://github.com/sayhi13/Projects/tree/main/asm-encrypter)** | Directory encrypter written in NASM (Netwide Assembler) targeting `x86-64`. | `x86-64` NASM assembly; note repo/list typo (`asm-enctypted`) |
| **[rfid_pn532_cloner](https://github.com/sayhi13/Projects/tree/main/rfid_pn532_cloner)** | Firmware for ESP32 paired with a PN532 NFC module, supporting cloning block `0` (UID) onto MIFARE Gen2 magic cards, SD-module integration, and T-Bank card support. | ESP32 + PN532 + SD module |
| **[sh2peer](https://github.com/sayhi13/Projects/tree/main/sh2peer)** | Peer-to-peer chat (`client <-> server`) implementation; currently without encryption. | Early / WIP networking prototype |

---

## Lab & Usage Notes

* **Authorized Environments Only:** Test network and RF/NFC tools (`arp-spoofer`, `rfid_pn532_cloner`) strictly on hardware, networks, and cards you own or have explicit permission to test.
* **Work in Progress:** Some utilities (such as `sh2peer`) are iterative prototypes—check individual repository `README`s or source files for build steps and current limitations.
