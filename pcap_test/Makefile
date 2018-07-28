pcap : pcap.o
	gcc -o pcap pcap.o -lpcap

pcap.o:	pcap.c
	gcc -c -o pcap.o pcap.c

clean :
	rm *.o pcap
