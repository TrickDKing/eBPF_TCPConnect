#!/usr/bin/env python3
# All IPv4 connection attempts are traced, even if they ultimately fail.

from __future__ import print_function
from bcc import BPF
from bcc.utils import printb

import os, sys
import signal, functools
from pathlib import Path

def check_privilege():
    if(os.geteuid() != 0):
        print("This script must be run as root or with sudo.")
        sys.exit(1)

# Custom exception class
# This is used to interrupt the eBPF program
class TerminateSignal(Exception):
    pass
    # Signal handler for SIGTERM

def handle_sigterm(signum, frame):
    raise TerminateSignal("Received SIGTERM, terminating...")

def LoadBPFProgram(fileName):
    '''Load and compile the eBPF program from the source file'''
    bpf_source = Path(fileName).read_text()
    bpf = BPF(text=bpf_source) # Compile the eBPF program
    return bpf

def PacketCounter(packet_count_map, prev_total_packets, total_packets):
    '''Print the number of packets that have been processed by the eBPF program'''
    for key in packet_count_map.keys():
        counter = packet_count_map[key]
        if(counter):
            total_packets += counter.value
    # Calculate the number of packets received per second
    packets_per_second = total_packets - prev_total_packets
    prev_total_packets = total_packets
    output = f"Collected packets flowing through interface: {total_packets}"
    sys.stdout.write(output + "\r")
    sys.stdout.flush()
    return prev_total_packets

def inet_ntoa(addr):
	dq = b''
	for i in range(0, 4):
		dq = dq + str(addr & 0xff).encode()
		if (i != 3):
			dq = dq + b'.'
		addr = addr >> 8
	return dq

def main():
    check_privilege()
    print("Executing script, running as root or with sudo.")
    # Creates a signal handler for SIGTERM
    signal.signal(signal.SIGTERM, handle_sigterm)
    bpf= LoadBPFProgram("tcp_probe.c") # Read the source code and launch to kernel
    # header
    print("%-6s %-12s %-16s %-16s %-4s" % ("PID", "COMM", "SADDR", "DADDR", "DPORT"))   

    while True:
        # Read messages from kernel pipe
        try:
            (task, pid, cpu, flags, ts, msg) = bpf.trace_fields()
            (_tag, saddr_hs, daddr_hs, dport_s) = msg.split(b" ")
        except ValueError:
            # Ignore messages from other tracers
            continue
        except (KeyboardInterrupt, TerminateSignal) as e:
            print(f"{e}. Interrupting eBPF tcp probe.")
            print("Detaching eBPF program and exiting.")
            # Detach the eBPF program from the network interface and clean up when the script is terminated
            #DetachXDPProgram(bpf, INTERFACE)
            break
        # Ignore messages from other tracers
        if _tag.decode() != "trace_tcp4connect":
            continue
        
        printb(b"%-6d %-12.12s %-16s %-16s %-4s" % (pid, task, inet_ntoa(int(saddr_hs, 16)), inet_ntoa(int(daddr_hs, 16)), dport_s))
        
        #    bpf.perf_buffer_poll()
        #    total_packets = 0
        #    prev_total_packets = PacketCounter(packet_count_map, prev_total_packets, total_packets)

if __name__ == "__main__":
    main()
