# secollect
Simple collector for inverter and optimiser data (S440 type) from SolardEdge HD Wave devices over RS485

Getting the data this way does not use or need any encryption it seems.

You will need a transparent IP/TCP bridge to RS485 (or use a bridge to RS232C and a converter to RS485).

The only thing this program does:

- report the current date+time to the inverter when it asks for it (it won't proceed when not supplied)
- when inverter data comes in, call an external program/script to do "something" with it
- when optimiser data comes in, call an external program/script to do "something" with it
- send ack's so the next record is sent.

Examples of such scripts are supplied.

usage:
    secollect [-i inverter-data-update-script] [-o optimiser-data-update-script] [-t time-offset in seconds]
            [-v loglevel] <host>
            log levels: 0 = error, 1 = warning, 2 = notice, 3 = info

The host is the name or ip address of a TCP to serial converter, it will connect at port 2424 and it will keep retrying when the port is unavailable.
There is NO serial device interface!

This is supposed to compile cleanly on very many Linux distributions, probably other Unix flavours as well, no specific features are used. It might even compile on Windows using MingW or similar (it does need the usual Unix/BSD socket abstraction layer and the poll system call or emulation).

There is no daemon mode because you're supposed to run it using systemd, which will take care of all the daemon stuff.

Some of the received packets are not parsed because I don't know what they're for and they consist of. If you do know, please inform me, notably the
"function 500, subfunction 50" packets which are huge, and the "function 3c2" packets.

If the Makefile doesn't work for you, there is no problem, you can compile all files yourself by hand and link them together to
secollect (secollect.o+crc16modbus.o), seanalyse (senanalyse.o+crc16modbus.o).

I've learned that the timestamps of the optmisers may be a few minutes off. You can use the -t option to correct them.

The seanalyse program is a simple data debugger, it takes a data stream on it's stdin. You can obtain it e.g. using wireshark. It should be data/payload only, no pcap file.
