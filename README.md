# MDK4

MDK is a proof-of-concept tool to exploit common IEEE 802.11 protocol weaknesses.

MDK4 is a new version of MDK3.

# About MDK3

MDK3 is a Wi-Fi testing tool from ASPj of k2wrlz, it uses the osdep library from the aircrack-ng project to inject frames on several operating systems.
Many parts of it have been contributed by the great aircrack-ng community:
Antragon, moongray, Ace, Zero_Chaos, Hirte, thefkboss, ducttape, telek0miker, Le_Vert, sorbo, Andy Green, bahathir, Dawid Gajownik and Ruslan Nabioullin.
THANK YOU!

MDK3 is licenced under the GPLv2 or later.

# About MDK4


MDK4 update plan:
- Support two wireless card, one for receiving data, another for injecting data.
- Support both 2.4 to 5 GHz
- Change the frequency hopping mechanism
   - Sniffing beacon frames sent by APs nearby, collect exists channels to hop.
- 802.11 packets replay
- A friendly console interface

Amok mode(option d)
- Handle more packet types when sniffing data frames to find targets
- Support block the specified ESSID/BSSID/Station MAC in command option

Others
- Refer to the MDK3 TODO list



