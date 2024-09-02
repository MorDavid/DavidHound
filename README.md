# DavidHound
This software is designed to collect data from Active Directory environments, similar to SharpHound. It provides various command-line options to gather information like:
- WebDAV
- Print Spooler
- IP addresses for every host
- Antivirus \ EDR installed on the machine
- LDAP signing status
- Pre2k
- Sessions

*Coming soon: SMB Signing, Kerberoast, ASREPRoast, SCCM.*

The tool uses multi-threading for efficient data collection across domains, making it useful for security assessments and AD environment auditing.

After collecting the data, the output file can be loaded into BloodHound/Neo4j using [MDLoader.py](https://github.com/MorDavid/MDLoader)

![Bloodhound Screenshot](./images/bh_screenshot.png)

## Usage
```

  █▀▄ █▀█ █ █ ▀█▀ █▀▄   █ █ █▀█ █ █ █▀█ █▀▄
  █ █ █▀█ ▀▄▀  █  █ █   █▀█ █ █ █ █ █ █ █ █
  ▀▀  ▀ ▀  ▀  ▀▀▀ ▀▀    ▀ ▀ ▀▀▀ ▀▀▀ ▀ ▀ ▀▀
                               By Mor David

Usage: [options]
Options:
  -h, --help              Show this help message and exit.
  -d, --domain [name]     Specify the domain name.
  -f, --file [file]       Specify the input file name.
  -o, --output [file]     Specify the output file name.
  -t, --threads [number]  Set the number of threads.
  -s, --sessions          Enable Sessions check.
  -wd, --webdav           Enable WebDAV check.
  -sp, --spooler          Enable Print Spooler check.
  -ip, --ips              Enable IP address check.
  -av, --antivirus        Enable antivirus check.
  -p2, --pre2k            Enable Pre2K check.
  -ls, --ldapsigning      Enable LDAP signing check.
```

## Disclaimer
- Some of the code in this program is derived from PingCastle.