#!/usr/bin/env python3
"""Linux verification stand-in for the CICIDS2017 Friday pipeline. NOT CICIDS2017 DATA.

usage: make_cicids_standin.py OUT_DIR [--offset 10800]
Writes OUT_DIR/standin.pcap and OUT_DIR/standin_flows.csv. The CSV imitates CICFlowMeter output
(columns Flow ID, Src IP, Src Port, Dst IP, Dst Port, Protocol, Timestamp, Flow Duration [microseconds],
Total Fwd Packet, Total Bwd packets, Label) with timestamps as local wall-clock time 'dd/mm/YYYY hh:mm:ss AM/PM',
deliberately shifted from the PCAP epoch by --offset seconds, so align.py must recover the offset.
Timeline (30 minutes from 07/07/2017 09:00:00 local): benign web flows throughout; PortScan from 172.16.0.1
at minutes 12-14 (1000 two-packet flows); DDoS from 172.16.0.1 at minutes 20-24; 40 flows labelled
'DDoS - Attempted' at minute 26 (no response packets)."""
import argparse, calendar, datetime, os, random, socket, struct, sys

def frame(src, dst, sport, dport, size, flags=0x10):
    payload = max(0, size - 54)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40 + payload, 0, 0, 64, 6, 0, socket.inet_aton(src), socket.inet_aton(dst))
    tcp = struct.pack("!HHIIHHHH", sport, dport, 0, 0, (5 << 12) | flags, 8192, 0, 0)
    return b"\xaa" * 6 + b"\xbb" * 6 + b"\x08\x00" + ip + tcp + bytes(payload)

def main():
    ap = argparse.ArgumentParser(); ap.add_argument("out"); ap.add_argument("--offset", type=float, default=10800.0); a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True); rnd = random.Random(7)
    local0 = datetime.datetime(2017, 7, 7, 9, 0, 0)
    naive0 = calendar.timegm(local0.timetuple())      # naive local time as if UTC
    pcap0 = naive0 + a.offset                          # the capture's true epoch
    flows = []; packets = []
    def flow(t, src, sport, dst, dport, nf, nb, dur, label, sizes=(60, 590, 1514)):
        flows.append((t, src, sport, dst, dport, dur, nf, nb, label))
        n = nf + nb
        for k in range(n):
            tk = t + (dur * k / max(1, n - 1) if n > 1 else 0.0)
            fwd = k % 2 == 0 if nb else True
            s, d, sp, dp = (src, dst, sport, dport) if fwd else (dst, src, dport, sport)
            packets.append((pcap0 + tk, frame(s, d, sp, dp, rnd.choice(sizes))))
    clients = ["192.168.10.%d" % i for i in range(5, 21)]; server = "192.168.10.50"
    t = 0.0
    while t < 1800.0:
        t += rnd.expovariate(3.0)
        nf = rnd.randint(2, 15); nb = rnd.randint(1, 15)
        flow(t, rnd.choice(clients), rnd.randint(1024, 65000), server, rnd.choice([80, 443]), nf, nb, rnd.uniform(0.05, 20.0), "BENIGN")
    for k in range(1000):
        flow(720.0 + k * 0.12, "172.16.0.1", 40000 + k % 20000, server, 1 + k, 1, 1, 0.0001, "PortScan", sizes=(60,))
    t = 1200.0
    while t < 1440.0:
        t += 0.05
        flow(t, "172.16.0.1", rnd.randint(1024, 65000), server, 80, 12, 8, rnd.uniform(0.5, 3.0), "DDoS")
    for k in range(40):
        flow(1560.0 + k * 0.5, "172.16.0.1", 30000 + k, server, 80, 1, 0, 0.0, "DDoS - Attempted", sizes=(60,))
    packets.sort(key=lambda p: p[0])
    with open(os.path.join(a.out, "standin.pcap"), "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for ts, d in packets:
            s = int(ts); us = int(round((ts - s) * 1e6))
            if us >= 1000000: s += 1; us -= 1000000
            fh.write(struct.pack("<IIII", s, us, len(d), len(d)) + d)
    with open(os.path.join(a.out, "standin_flows.csv"), "w") as fh:
        fh.write("Flow ID, Src IP, Src Port, Dst IP, Dst Port, Protocol, Timestamp, Flow Duration, Total Fwd Packet, Total Bwd packets, Label\n")
        for t, src, sport, dst, dport, dur, nf, nb, label in sorted(flows):
            ts = (local0 + datetime.timedelta(seconds=t)).strftime("%d/%m/%Y %I:%M:%S %p")
            fh.write("%s-%s-%d-%d-6, %s, %d, %s, %d, 6, %s, %d, %d, %d, %s\n" % (src, dst, sport, dport, src, sport, dst, dport, ts,
                     int(round(dur * 1e6)), nf, nb, label))
    print("stand-in written: %d packets, %d flows, offset %.0f s" % (len(packets), len(flows), a.offset))

if __name__ == "__main__":
    main()
