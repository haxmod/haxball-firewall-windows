# HaxBall Firewall for Windows
Unfortunately, some people think it is funny to crash HaxBall rooms by using modified clients to flood game hosts.
These crashes are either induced by joining a room multiple times or by flooding the host with an amount of packets that is sufficient to overstress Flash.
Since these issues cannot be fixed at the Flash layer, this firewall aims to be an external helper to prevent these attacks from impacting the game performance.

## Why does it require administrator privileges?
This application makes use of application programming interfaces (APIs) which enable the inspection and suppression of network packets.
They require elevated privileges because they can potentially be abused to spy on your network traffic.

## Download
Now, the firewall comes in two flavors: Normal and Anti-VPN/Proxy.\
The latter will also drop any traffic from IP addresses belonging to data centers. As a consequence, trolls using VPNs or proxies will not be able to connect to your room.

|Flavor|Link| 
|-|-| 
|Normal|[Download](https://github.com/haxmod/haxball-firewall-windows/releases/download/0.4.7/HaxWall.exe)|
|Anti-VPN/Proxy|[Download](https://github.com/haxmod/haxball-firewall-windows/releases/download/0.4.7/HaxWall-DC.exe)|

It should suffice to store the executable somewhere and run it whenever you are hosting a room. If this is not the case, have a look at the section below.

## Problems
### Missing IP address logging
The firewall should display the IP addresses of players that join your room. Under certain unknown circumstances, the Windows Firewall might interfere with the HaxBall firewall.\
If you do not see any IP address logs, retry running the HaxBall firewall with the Windows Firewall disabled.

In case you have any other problems running the firewall, create a GitHub issue and describe your problem there.
Make sure to include any relevant information about your operating system.

## Screenshot
Successfully running the firewall should look similar to this:

![Screenshot](https://raw.githubusercontent.com/haxmod/binary-data/master/img/screenshot-windows.png)
