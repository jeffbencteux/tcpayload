#!/usr/bin/python
# Small scapy wrapper to establish a TCP connection and send a payload

import argparse
from scapy.all import *
conf.L3socket = L3RawSocket

def send_handshake(saddr, daddr, sport, dport, isn, sleeptime):
	SYN = IP(src=saddr, dst=daddr)/TCP(sport=sport, dport=dport, flags="S", seq=isn)
	time.sleep(sleeptime)
	SYNACK = sr1(SYN)
	ACK = IP(src=saddr, dst=daddr)/TCP(sport=sport, dport=dport, seq=SYNACK.ack, ack=SYNACK.seq + 1, flags="A")
	time.sleep(sleeptime)
	send(ACK)
	return (SYNACK.ack, SYNACK.seq + 1)

def send_payload(saddr, daddr, sport, dport, payload, next_seq, next_ack, sleeptime, mss):
	nb_segs = len(payload) / mss

	if (len(payload) % mss != 0):
		nb_segs = nb_segs + 1

	for i in range(0, nb_segs):
		sub_payload = payload[i * mss: (i + 1) * mss]

		DATA = IP(src=saddr, dst=daddr)/TCP(sport=sport, dport=dport, flags="A", seq=next_seq, ack=next_ack)/sub_payload
		time.sleep(sleeptime)
		ANS1 = sr1(DATA)
		next_seq=ANS1.ack
		next_ack=ANS1.seq

	return (next_seq, next_ack)

def send_fin_close(saddr, daddr, sport, dport, next_seq, next_ack, sleeptime):
	FIN = IP(src=saddr, dst=daddr)/TCP(sport=sport, dport=dport, flags="FA", seq=next_seq, ack=next_ack)
	time.sleep(sleeptime)
	FINACK = sr1(FIN)
	ACK2 = IP(src=saddr, dst=daddr)/TCP(sport=sport, dport=dport, seq=FINACK.ack, ack=FINACK.seq + 1, flags="A")
	time.sleep(sleeptime)
	send(ACK2)

def send_rst_close(saddr, daddr, sport, dport, sleeptime):
	RST = IP(src=saddr, dst=daddr)/TCP(sport=sport, dport=dport, flags="FA", seq=ANS1.ack, ack=ANS1.seq)
	time.sleep(sleeptime)
	RSTACK = sr1(FIN)

def main():
	parser = argparse.ArgumentParser(description="The ultimate TCP payload wrapper around Scapy")
	parser.add_argument("SADDR", help="Source IP adress")
	parser.add_argument("--sport", help="Source port (default is random in [1024, 65535])", type=int, default=random.randrange(1024, 65535))
	parser.add_argument("DADDR", help="Destination IP adress")
	parser.add_argument("DPORT", help="Destination port", type=int)
	parser.add_argument("-p", "--payload", help="Payload to be sent over TCP", default="Some data")
	parser.add_argument("--bytestring", help="Treat payload as bytestring (escape with \\xHH)", action="store_true")
	parser.add_argument("--endswith-fin", help="Tear down connection with a FIN segment (default)", action="store_true")
	parser.add_argument("--endswith-rst", help="Tear down connection with a RST segment", action="store_true")
	parser.add_argument("--isn", type=int, default=0, help="Initial sequence number (default is 0)")
	parser.add_argument("--sleeptime", type=int, default=0, help="Sleep 'n' seconds between segments")
	parser.add_argument("--mss", type=int, default=1500, help="customize Maximum Segment Size (MSS) in octets (break payload in several segments)")
	args = parser.parse_args()

	if args.bytestring:
		payload = args.payload.decode('string-escape')
	else:
		payload = args.payload

	next_seq, next_ack = send_handshake(args.SADDR, args.DADDR, args.sport, args.DPORT, args.isn, args.sleeptime)
	next_seq, next_ack = send_payload(args.SADDR, args.DADDR, args.sport, args.DPORT, payload, next_seq, next_ack, args.sleeptime, args.mss)

	if args.endswith_fin:
		send_fin_close(args.SADDR, args.DADDR, args.sport, args.DPORT, next_seq, next_ack, args.sleeptime)
	elif args.endswith_rst:
		send_rst_close(args.SADDR, args.DADDR, args.sport, args.DPORT, next_seq, next_ack, args.sleeptime)
	else:
		# Close with FIN by default
		send_fin_close(args.SADDR, args.DADDR, args.sport, args.DPORT, next_seq, next_ack, args.sleeptime)

main()
