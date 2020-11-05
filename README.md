# packet-sniffer
do `sudo bash ./nic.sh managed` to put NIC in managed mode
do `sudo bash ./nic.sh monitor` to put NIC in monitor mode
do `sudo python wireless -i [interface_name]` to run wireless sniffer 
WIRELESS:
From left to right:

1. timestamp from the system clock
2. transmission time of the packet (in us)
3. IEEE-802.11 physical layer (either "b", "g", "n", or "ac")
4. size of the packet (in bytes)
5. frame type (0=management, 1=control, 2=data)
6. frame subtype
7. source address
8. destination address
9. frame sequence number
10. frame fragment number
11. channel (MHz)
12. data rate (Mbps)
13. signal strength (RSSI)
