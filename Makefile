# Makefile for pcap-test

TARGET = pcap-test
SRC = pcap-test.c

all:
	gcc -o $(TARGET) $(SRC) -lpcap

clean:
	rm -f $(TARGET)

.PHONY: all clean