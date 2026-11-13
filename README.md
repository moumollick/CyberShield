# CyberShield

A small firewall / network-security simulation written in C++ with OpenGL (freeglut).
Normal and attack packets travel from client PCs through a firewall to a DMZ web server
or the internal database. The firewall inspects each packet and allows, rate-limits or blocks it.

## Setup (Windows)
1. Install MSYS2 (C:\msys64), then in the **MSYS2 UCRT64** terminal:
   `pacman -S mingw-w64-ucrt-x86_64-gcc mingw-w64-ucrt-x86_64-gdb mingw-w64-ucrt-x86_64-freeglut make`
2. Add `C:\msys64\ucrt64\bin` to the Windows PATH and restart VS Code.

## Build and run
Run from the project folder (so `config/firewall.cfg` is found):

    g++ -std=c++17 src/main.cpp src/Renderer.cpp src/Network.cpp src/Firewall.cpp src/AttackGenerator.cpp src/Dashboard.cpp src/IDS.cpp -o CyberShield.exe -lfreeglut -lopengl32 -lglu32
    .\CyberShield.exe

If the project has more .cpp files (for example `src/Challenge.cpp`), add them to the command.

## Controls
| Key / mouse | Action |
|---|---|
| N | send one normal packet |
| 1 - 6 | Flood/DDoS, Port scan, Malware, Brute force, Oversized packet, Blacklisted host |
| D | automatic demo (about 33 s), summary and log save at the end |
| S | show / hide the summary screen |
| L | save report to `logs/events.txt` (also saved on Esc) |
| Click a packet | packet inspector (header, matched rule, threat) |
| Click a rule or F1 - F6 | switch rule R1 - R6 on / off |
| Arrow keys | up/down select a limit (max size, rate limit, ban time...), left/right change it |
| Space, + / -, R, Esc | pause, speed, reset (reloads config), exit |

## Firewall rules
| Rule | Meaning | Action |
|---|---|---|
| R1 | Source IP in blacklist | block |
| R2 | Destination port in risky list (23, 445, 3389) | block |
| R3 | Packet larger than `maxSize` | block |
| R4 | More than `rateLimitN` packets per window from one source | rate-limit, then block (auto-ban) |
| R5 | Known malware signature | block |
| R6 | Too many failed logins | block |
| R7 | Everything else | allow |

All limits, the blacklist, ports and signatures are set in `config/firewall.cfg`.
Edit the file and press R to reload it.

## IDS (Week 5)
The firewall decides per packet. The IDS watches behaviour over time and shows a popup alert:
6 different ports from one source in 3 s (port scan), 12 packets in 1 s (flood),
3 failed logins in 10 s (brute force), a payload signature, an oversized packet, a blacklisted host.
It works even if the matching firewall rule is switched off, so you can compare detection and prevention.

## Graphics algorithms (where they are used)
- DDA line: background grid
- Bresenham line: network links and the X on blocked packets
- Midpoint circle: ring around every node, selection ring, expanding rings where packets are blocked, gauge hub
- Bresenham also draws the threat gauge ticks and needle
- Fading packet tail, red border flash when status is CRITICAL
- Translation: packet movement from node to node (`Network::update`)

## Files
- `Renderer.*`: DDA, Bresenham, midpoint circle, rectangles, text
- `Node.h`, `Packet.h`, `Network.*`: network model, packet movement, statistics, log saving
- `Firewall.*`: rules R1 - R7, rate limiter, config loading
- `AttackGenerator.*`: the six attacks and the demo scenario
- `Dashboard.*`: right-side panel, packet inspector, summary screen
- `IDS.*`: intrusion detection (port scan, flood, brute force, malware, oversized, blacklist alerts)
- `Logger.h`: event log

## Viva notes (functions to understand)
- `Firewall::inspect()`: rules are checked in order R1 to R7, the first match decides.
- `Network::onReachFirewall()`: runs once per packet at the firewall, applies the decision and updates counters.
- `Network::selectAt()`: finds the packet nearest to the mouse click.
- `Firewall::loadConfig()`: reads `key = value` lines from the config file.
- `IDS::observe()`: keeps per-source history and raises an alert when a pattern is found.
- `Network::saveLog()`: writes statistics and the full event log to a text file.