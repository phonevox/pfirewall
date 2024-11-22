# Quickstart

Download the latest tag (one liner)
```sh
curl -s https://api.github.com/repos/phonevox/pfirewall/releases/latest | grep '"tag_name":' | sed 's/.*"tag_name": "\(.*\)",/\1/' | xargs -I {} curl -skL https://github.com/phonevox/pfirewall/archive/refs/tags/{}.tar.gz | tar xz --transform="s,^[^/]*,pfirewall,"
```

Access the repository's folder
```
cd ./pfirewall
```

Install to your path, update, or straight up use the application
```sh
./pfirewall --install # adds to system path (specifically /usr/sbin/pfirewall), call with 'pfirewall -h'
./pfirewall --update # update to most recent github tag. not necessary if you just cloned the repository
./pfirewall --help # shows how to use the app
```

If you installed it to your path, you can run the following from anywhere in your system:
```sh
pfirewall --help # shows how to use the app
pfirewall -d -vv -e iptables # runs in dry mode, super verbose, on iptables engine
pfirewall --update
pfirewall -V # checks the current version
```

---
## NOTE:
If you execute the app on a "CENTOS-like" OS (centos, rocky), it will assume the default firewall engine is "iptables" (with fail2ban). Else if you execute the app on a Debian based host, it will assume the default firewall engine is "firewalld".

**FOR IPTABLES WITH FAIL2BAN, BEWARE**: 
Fail2ban is annoying. Run this script to fix your rules in iptables. The INPUT jail order must preserve: 1. EXCEPTIONS, 2. FAIL2BAN INPUT, 3. PORT DROPS. In that exact order. Check your rules with `iptables -nL INPUT`


