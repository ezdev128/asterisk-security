## Asterisk security

External Asterisk security monitor for fail2ban

## Configuring extsecurity.py

- Place extsecurity.py to /var/lib/asterisk/security/extsecurity.py
- Edit /var/lib/asterisk/security/extsecurity.py (if required)
```
settings = {
    "logfile_path": "/var/log/asterisk/inbound_extsecurity.log",
    "default_sleep_protection_time_sec": 2,
    "alert_if_callerid_num_is_not_numeric": True,
    "alert_if_dialed_exten_is_not_numeric": True,
    "alert_if_dialed_exten_lenghts_less_than": 10,
    "alert_if_dialed_exten_lenghts_more_than": 14,
    "automatic_block_attempts_to_extensions": [
        ur"\d{1,3}",
    ],
}
```
- Give +x permissions to /var/lib/asterisk/security/extsecurity.py


## Configuring asterisk

- Place to inbound (default) dialplan the following lines:
```
[default]
exten => s,1,System(/var/lib/asterisk/security/extsecurity.py '{"ip": "${CHANNEL(peerip)}", "callerid_num": "${CALLERID(num)}", "callerid_num": "${CALLERID(name)}", "dest_exten": "${EXTEN}", "user_agent": "${CHANNEL(useragent)}", "peer_name": "${CHANNEL(peername)}"}')
exten => _X.,1,System(/var/lib/asterisk/security/extsecurity.py '{"ip": "${CHANNEL(peerip)}", "callerid_num": "${CALLERID(num)}", "callerid_num": "${CALLERID(name)}", "dest_exten": "${EXTEN}", "user_agent":"${CHANNEL(useragent)}", "peer_name": "${CHANNEL(peername)}"}')
exten => _+X.,1,System(/var/lib/asterisk/security/extsecurity.py '{"ip": "${CHANNEL(peerip)}", "callerid_num": "${CALLERID(num)}", "callerid_num": "${CALLERID(name)}", "dest_exten": "${EXTEN}", "user_agent":"${CHANNEL(useragent)}", "peer_name": "${CHANNEL(peername)}"}')
```
- Reload dialplan


## Configuring fail2ban

- Add to /etc/fail2ban/jail.conf
```
[ast-inb-extsec]
enabled = true
port    = 5060
protocol = udp
filter  = asterisk-inbound-extsecurity
maxretry = 1
logpath = /var/log/asterisk/inbound_extsecurity.log
bantime = 86400
findtime = 3600
action  = iptables-allports[name=ASTERISK, protocol=all]
```
- Create file /etc/fail2ban/filter.d/asterisk-inbound-extsecurity.conf
- Add to file /etc/fail2ban/filter.d/asterisk-inbound-extsecurity.conf
```
[INCLUDES]
#before = common.conf

[Definition]
failregex = ERROR ip=<HOST> reason=.*
ignoreregex =
```
- Restart fail2ban


