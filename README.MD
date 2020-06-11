-u AMI username
-p aterisk AMI password
-i aterisk IP address
-dp asterisk AMI port, default 5038
-peers peers for monitoring, may be single number or multiple comma separated list like: 101,102,703,805

=======================================================================================================================
Sensor for PRTG monitoring system.
For monitoring SIP peers.
Asterisk version lower than 12 do not have REST API but have AMI interface, this sensor utilize AMI.

License GPL
Author Volkov Oleg, PowerC 2020
oleg@powerc.ru
=======================================================================================================================

Aterisk configuration:
1. Add user to manager.conf
2. Add permition for Your subnet to manager.conf
3. Enable manager in manager.conf

Like this:

[prtg]
deny=0.0.0.0/0.0.0.0
permit=192.168.0.0/24
permit=192.168.1.0/24
secret = prtg
read = system,call,log,verbose,agent,user,config,dtmf,reporting,cdr,dialplan
write = system,call,agent,user,config,command,reporting,originate

[general]
enabled = yes
port = 5038
bindaddr = 0.0.0.0


