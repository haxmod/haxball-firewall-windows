# HaxBall Firewall for Windows
Unfortunately, some people think it is funny to crash HaxBall rooms by using modified clients to flood game hosts.
These crashes are either induced by joining a room multiple times or by flooding the host with an amount of packets that is sufficient to overstress Flash.
Since these issues cannot be fixed at the Flash layer, this firewall aims to be an external helper to prevent these attacks from impacting the game performance.

## Why does it require administrator privileges?
This application makes use of application programming interfaces (APIs) which enable the inspection and suppression of network packets.
They require elevated privileges because they can potentially be abused to spy on your network traffic.

## Download
The most recent executable version can be found [here](https://github.com/haxmod/haxball-firewall-windows/releases/download/0.2.0/HaxWall.exe).

It should suffice to store the executable somewhere and run it whenever you are hosting a room. If this is not the case, have a look at the section below.

## Problems
In case you have problems running the firewall, create a GitHub issue and describe your problem there.
Make sure to include any relevant information about your operating system.