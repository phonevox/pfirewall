If you execute the app on a "CENTOS-like" OS (centos, rocky), it will assume the default firewall engine is "iptables" (with fail2ban). Else if you execute the app on a Debian based host, it will assume the default firewall engine is "firewalld".

FOR IPTABLES WITH FAIL2BAN, BEWARE: Fail2ban is annoying. Run this script to fix your rules in iptables. The INPUT jail order must preserve: 1. EXCEPTIONS, 2. FAIL2BAN INPUT, 3. PORT DROPS. In that exact order. Check your rules with `iptables -nL INPUT`

```sh
./pfirewall --install # adds to system path (specifically /usr/sbin/pfirewall), call with 'pfirewall -h'
./pfirewall --help # shows how to use the app
./pfirewall --update # update to most recent github tag. not necessary if you just cloned the repository
```
