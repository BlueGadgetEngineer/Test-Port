# Test-Port
Identify if a port is open and attempt to identify a device further by querying Active Directory for a canonical name.

.Example

Test-Port -Name MyComputer -Port 80 -Protocol TCP

Name          : MyComputer
CanonicalName : MyDomain.Local/Computers/MyComputer
IP            : 192.168.1.23
Port          : 80
Protocol      : TCP
Online        : Online
PortStatus    : Open

.Example


Test-Port -IPaddress 192.168.1.15 -Port 443 -Protocol TCP

Name          : MyComputer
CanonicalName : MyDomain.Local/Computers/MyComputer
IP            : 192.168.1.15
Port          : 443
Protocol      : TCP
Online        : Online
PortStatus    : Open
