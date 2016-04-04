import json
class Stats:
    def __init__(self, outputFile):
        self.outputFile = outputFile
        self.data = {'TotalPackets': 0,'TotalTcpPackets': 0,'RTT': {},'TimeSeq': {}, 'Bandwidth': {}, 'Window': {}}
        self.tmpData = {'Bandwidth': {}}

    def save(self):
        self.preSaveActions();
        # Output file: data = '[{"name" : "Harry", "age" : "32"}]';
        with open(self.outputFile, 'w') as outFile:
            outFile.write('data = \'')
            json.dump(self.data, outFile)
            outFile.write('\';')

    def addToLabeledDict(self, dictionary, tcpConnection, value):
        label = tcpConnection.getSrcIp() + "->" + tcpConnection.getDstIp()
        if label not in dictionary:
            dictionary[label] = []

        dictionary[label].append(value)

    def addPacket(self):
        self.data['TotalPackets'] = self.data['TotalPackets'] + 1

    def addTcpPacket(self):
        self.data['TotalTcpPackets'] = self.data['TotalTcpPackets'] + 1

    def addRTTItem(self, tcpConnection, timeInterval, sequenceNumber):
        self.addToLabeledDict(self.data['RTT'], tcpConnection, (sequenceNumber, timeInterval * 1000))

    def addTimeSeqItem(self, tcpConnection, timestamp, sequenceNumber):
        self.addToLabeledDict(self.data['TimeSeq'], tcpConnection, (timestamp, sequenceNumber))

    def addTimeLengthItem(self, tcpConnection, timestamp, length):
        self.addToLabeledDict(self.tmpData['Bandwidth'], tcpConnection, (timestamp, length))

    def addWindowItem(self, tcpConnection, timestamp, size):
        self.addToLabeledDict(self.data['Window'], tcpConnection, (timestamp, size))

    def preSaveActions(self):
        # Compute avg RTT
        AVGRoundTripTime = 0
        for label, value in self.data['RTT'].iteritems():
            if len(value) > 0:
                rttList = [ seq[1] for seq in value ]
                AVGRoundTripTime += sum(rttList) / len(rttList)

        self.data['AVGRoundTripTime'] = AVGRoundTripTime

        lengthAggr = 0
        for key, value in self.tmpData['Bandwidth'].iteritems():
            self.data['Bandwidth'][key] = []
            for (timestamp, length) in value:
                lengthAggr += length
                bandwidth = lengthAggr / timestamp if timestamp != 0 else 0
                self.data['Bandwidth'][key].append((timestamp, bandwidth))