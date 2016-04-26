#!/usr/bin/env python2

import dpkt
# To encode ip adresses
import socket
import sys
from stats import Stats

# Converts byte array to int
def from_bytes (data):
    if isinstance(data, str):
        data = bytearray(data)
    num = 0
    for offset, byte in enumerate(data):
        num += byte << (offset * 8)
    return num

class TcpConnection:
    def __init__(self, srcIp, dstIp, srcPort, dstPort):
        self.srcIp = srcIp
        self.dstIp = dstIp
        self.srcPort = srcPort
        self.dstPort = dstPort

    def getSrcPort(self):
        return self.srcPort

    def getDstPort(self):
        return self.dstPort

    def getSrcIp(self):
        return self.srcIp

    def getDstIp(self):
        return self.dstIp

    def equels(self, tcpCon):
        return tcpCon.getSrcIp() == self.srcIp and tcpCon.getDstIp() == self.dstIp \
               and tcpCon.getSrcPort() == self.srcPort and tcpCon.getDstPort() == self.dstPort

    def isPairConnection(self, tcpCon):
        return tcpCon.getSrcIp() == self.dstIp and tcpCon.getDstIp() == self.srcIp \
               and tcpCon.getSrcPort() == self.dstPort and tcpCon.getDstPort() == self.srcPort

class TcpAdvanced(TcpConnection):
    def __init__(self, srcIp, dstIp, srcPort, dstPort, seqNumber, timestamp, windowScaling):
        TcpConnection.__init__(self, srcIp, dstIp, srcPort, dstPort)
        self.seqNumber = seqNumber
        self.timestamp = timestamp
        self.windowScaling = windowScaling

    def getTimestamp(self):
        return self.timestamp

    def getSeqNumber(self):
        return self.seqNumber

    def getWindowScaling(self):
        return self.windowScaling

class Streams:
    def __init__(self):
        self.streams = []

    def addStream(self, tcpConnection):
        self.streams.append(tcpConnection)

    def getSeqNumber(self, tcpConnection):
        # Returns first or zero 
        return next((x.getSeqNumber() for x in self.streams if tcpConnection.equels(x)), 0)

    def getTimeStamp(self, tcpConnection):
        # Returns first or zero 
        return next((x.getTimestamp() for x in self.streams if tcpConnection.equels(x)), 0)

    def getWindowScaling(self, tcpConnection):
        # Returns first or zero 
        return next((x.getWindowScaling() for x in self.streams if tcpConnection.equels(x)), 0)

class RTTList:
    def __init__(self):
        self.list = []

    def addPacket(self, tcpConnection, sequenceWithLength, timestamp):
        self.list.append((tcpConnection, sequenceWithLength, timestamp))

    def getAcknowledgedPackets(self, tcpConnection, acknowledgment):
        packets = [x for x in self.list if tcpConnection.isPairConnection(x[0]) and x[1] <= acknowledgment]
        for packet in packets:
            self.list.remove(packet)
        return packets

class Analyzer:
    def __init__(self, stats):
        self.rtt = RTTList()
        self.stats = stats
        self.streams = Streams()

    def analyze(self, tcpPacket, tcpConnection):
        self.stats.addTcpPacket()
        self.innerAnalyze(tcpPacket, tcpConnection)

    # Need refactoring - multiple searching for tcp connection and multiple local variables
    def innerAnalyze(self, tcpPacket, tcpConnection):
        # We have got SYN packet with ACK flag
        if ( tcpPacket.flags & dpkt.tcp.TH_SYN ) != 0:
            self.streams.addStream(tcpConnection)
            
        initialTimestamp = self.streams.getTimeStamp(tcpConnection)
        initialSeqNumber = self.streams.getSeqNumber(tcpConnection)
        relativeTimestamp = tcpConnection.getTimestamp() - initialTimestamp
        relativeSeqNumber = tcpPacket.seq - initialSeqNumber
        self.stats.addTimeLengthItem(tcpConnection, relativeTimestamp, len(tcpPacket.data))
        self.stats.addTimeSeqItem(tcpConnection, relativeTimestamp, relativeSeqNumber)
        if len(tcpPacket.data) > 0:
            self.rtt.addPacket(tcpConnection, tcpPacket.seq + len(tcpPacket.data), tcpConnection.getTimestamp())

        # Compute Window size
        #if ( tcpPacket.flags & dpkt.tcp.TH_SYN ) == 0:
        windowScaling = self.streams.getWindowScaling(tcpConnection)
        self.stats.addWindowItem(tcpConnection, relativeTimestamp, tcpPacket.win * windowScaling)

        # We have got TCP packet with ACK flag
        if ( tcpPacket.flags & dpkt.tcp.TH_ACK ) != 0:
            acknowledgmentPackets = self.rtt.getAcknowledgedPackets(tcpConnection, tcpPacket.ack)
            for packet in acknowledgmentPackets:
                relativeSeqNumber = packet[1] - self.streams.getSeqNumber(packet[0])
                self.stats.addRTTItem(packet[0], tcpConnection.getTimestamp() - packet[2], relativeSeqNumber)

if len(sys.argv) != 2:
    print r"Script have to be launched with 1 parameter"
    print r"Excample: ./python2 tcpstats.py sample.pcap"
    sys.exit()

stats = Stats('log/result.js')
analyzer = Analyzer(stats)

with open(sys.argv[1], "rb") as readFile:
    pcap = dpkt.pcap.Reader(readFile)

    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)

        if eth.type != dpkt.ethernet.ETH_TYPE_IP:
            continue

        ip = eth.data
        stats.addPacket()
        
        if ip.p==dpkt.ip.IP_PROTO_TCP: #Check for TCP packets
            tcp = ip.data
            opts = dpkt.tcp.parse_opts(tcp.opts)
            windowScalingShift = next((from_bytes(x[1]) for x in opts if x[0] == 3), 0)
            tcpConnection = TcpAdvanced(socket.inet_ntoa(ip.src), socket.inet_ntoa(ip.dst), \
                tcp.sport, tcp.dport, tcp.seq, ts, pow(2, windowScalingShift))

            analyzer.analyze(tcp, tcpConnection);
            
        elif ip.p==dpkt.ip.IP_PROTO_UDP: #Check for UDP packets
            UDP=ip.data 


stats.save()