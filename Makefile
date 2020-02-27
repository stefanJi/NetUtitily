arp: src/arp.cpp src/include/log.h
	g++ -I src/include src/arp.cpp -o arp
ping: src/ping.cpp src/include/log.h
	g++ -I src/include src/ping.cpp -o ping

