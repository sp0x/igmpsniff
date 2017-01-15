import pcap
import dpkt

import sys
import string
import time
import socket
import struct

import compat



class IgmpHandler:
    protocols = {socket.IPPROTO_TCP: 'tcp',
                 socket.IPPROTO_UDP: 'udp',
                 socket.IPPROTO_ICMP: 'icmp',
                 socket.IPPROTO_IGMP: 'igmp'}
    igmpPacketTypes = {
        17: 'mship_query',  # 0x11
        22: 'mship_report',  # 0x16
        23: 'mship_leave'  # 0x17
    }
    # destination - [ messageType, destinationName ]
    igmpDestinations = {
        '224.0.0.2': ('query', 'all_routers'),
        '224.0.0.1': ('leave', 'all_systems')
    }

    def __init__(self, pcap_object):
        self.pcaper = pcap_object
        self.on_pk = lambda tm, tp_ip, tp_mac, tp_igmp: None

    def handle_live(self, plen, buff, ts):
        self.handle(plen, buff, ts)

    def handle(self, plen, buff, ts):
        """
        Handles packets and whenever an igmp packet is found,
         parses it and calls on_pk( (ts, (ipSrc, ipDst), (macSrc, macDst), (igmpType, igmpGroup, igmpVer) ) ) .
        Use IgmpHandler.set_on_packet to add a handler.
        :param plen:
        :param buff:
        :param ts:
        :return:
        """
        # self.print_packet(len(buff), buff, ts)
        eth = dpkt.ethernet.Ethernet(buff)
        ip = eth.data 
        if type(ip.data) == dpkt.igmp.IGMP:
            pk_igmp = ip.data
            str_igmp = str(pk_igmp)
            # igbytes = (bytes(igmpPack)[0])
            # igmp_type = self.igmpPacketTypes[pk_igmp.type]
            igmp_gr = pcap.ntoa(struct.unpack('i', str_igmp[4:8])[0])
            ver = ip.p
            addrs_mac = (self.mac_addr(eth.src), self.mac_addr(eth.dst))
            addrs_ip = (self.inetAddrStr(ip.src), self.inetAddrStr(ip.dst)) 
            self.on_pk(ts, addrs_ip, addrs_mac, (pk_igmp.type, igmp_gr, ver))

    def set_on_packet(self, on_packet):
        """
        Sets a callback which is invoked with the following argument: ( (ts, (ipSrc, ipDst), (macSrc, macDst),
         (igmpType, igmpGroup, igmpVer) ) ) .
        :param on_packet:
        :return:
        """
        self.on_pk = on_packet
        return self

    def capture(self):
        try:
            while 1:
                self.pcaper.dispatch(1, self.handle_live)
        except KeyboardInterrupt:
            print '%s' % sys.exc_type
            print 'shutting down'
            print '%d packets received, %d packets dropped, %d packets dropped by interface' % self.pcaper.stats()

    def open_and_handle(self, filename):
        f = open(filename)
        reader = dpkt.pcap.Reader(f)
        for ts, buf in reader:
            self.handle(len(buf), buf, ts)
        f.close()

        pass

    # region Utilities
    @staticmethod
    def mac_addr(address):
        return ':'.join('%02x' % compat.compat_ord(b) for b in address)
    @staticmethod
    def inetAddrStr(inet):
        try:
            return socket.inet_ntop(socket.AF_INET, inet)
        except ValueError:
            return socket.inet_ntop(socket.AF_INET6, inet)

    @staticmethod
    def decode_ip_packet(s):
        d = {}
        d['version'] = (ord(s[0]) & 0xf0) >> 4
        d['header_len'] = ord(s[0]) & 0x0f
        d['tos'] = ord(s[1])
        d['total_len'] = socket.ntohs(struct.unpack('H', s[2:4])[0])
        d['id'] = socket.ntohs(struct.unpack('H', s[4:6])[0])
        d['flags'] = (ord(s[6]) & 0xe0) >> 5
        d['fragment_offset'] = socket.ntohs(struct.unpack('H', s[6:8])[0] & 0x1f)
        d['ttl'] = ord(s[8])
        d['protocol'] = ord(s[9])
        d['checksum'] = socket.ntohs(struct.unpack('H', s[10:12])[0])
        d['source_address'] = pcap.ntoa(struct.unpack('i', s[12:16])[0])
        d['destination_address'] = pcap.ntoa(struct.unpack('i', s[16:20])[0])
        if d['header_len'] > 5:
            d['options'] = s[20:4 * (d['header_len'] - 5)]
        else:
            d['options'] = None
        d['data'] = s[4 * d['header_len']:]
        return d

    @staticmethod
    def dump_hex(s):
        bytes = map(lambda x: '%.2x' % x, map(ord, s))
        out = ""
        rows = len(bytes) / 16
        for i in xrange(0, len(bytes) / 16):
            x1 = string.join(bytes[i * 16:(i + 1) * 16], ' ')
            x2 = string.join(bytes[(i + 1) * 16:], ' ')
            print '    %s' % x1
            print '    %s' % x2
            out += '    %s' % x1 + '    %s' % x2
        if rows == 0:
            print ' '.join(bytes)
            out += ' '.join(bytes)
        return out

    @staticmethod
    def print_packet(pktlen, data, timestamp):
        protocols = IgmpHandler.protocols;

        if not data:
            return

        if data[12:14] == '\x08\x00':
            decoded = IgmpHandler.decode_ip_packet(data[14:])
            print '	%s.%f %s > %s PROTO %s' % (time.strftime('%H:%M',
                                                     time.localtime(timestamp)),
                                       timestamp % 60,
                                       decoded['source_address'],
                                       decoded['destination_address'],
									   protocols[decoded['protocol']])
            #for key in ['version', 'header_len', 'tos', 'total_len', 'id',
            #            'flags', 'fragment_offset', 'ttl']:
            #    print '  %s: %d' % (key, decoded[key]) 
            #print '  header checksum: %d' % decoded['checksum']
            #print '  data:'
            # IgmpHandler.dump_hex(decoded['data'])



# endregion
