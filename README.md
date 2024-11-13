```txt
Usage:
  pfirewall [flags]

Description:
  This script aims to set the default firewall rules used by Phonevox, with their default IPs and ports, plus the possibility of adding extra IPs and ports.

Flags:
  --install               Add this script to the system path and exits
  -vv, --super-verbose    Enter super verbose mode, and show all commands made
  -v, --verbose           Verbose mode
  -s string               IPs to whitelist on top of defaults. Example: 0.0.0.0/0,192.168.1.1
  -p string               Ports to drop on top of defaults. Example: 20-23/tcp,5060,80/udp,80/tcp,443:force
  -d, --dry               Do NOT make changes to the system
  -c, --check             Checks all flags and values, and exit
  -l, --list              List current firewall rules/configuration and exit
  -h, --help              Shows this help
  -V, --version           Show app version and exit
  --ignore-failsafe       Do NOT use the failsafe system
  --update                Update this script to the newest version
  --ignore-defaults       Do NOT use default ports and IPs
  --ignore-default-ips    Do NOT use default IPs
  --ignore-default-ports  Do NOT use default ports
  --no-flush              Do NOT flush zones
```
