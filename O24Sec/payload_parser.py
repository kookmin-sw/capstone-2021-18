# Returns application payload about each protocols
def get_app(payload):
    # ethernet length
    length = 27
    # ipv4 length
    length += (int(payload[length + 2], 16)) * 8
    # tcp
    if payload[46:48] == "06":
        length += (int(payload[length + 25], 16)) * 8
        return payload[length + 1:]
    # udp
    elif payload[46:48] == "11":
        return payload[length + 9:]
    # icmp
    elif payload[46:48] == "01":
        return payload

def to_byte(payload):
    out = []
    for ii in range(0, len(payload), 2):
        out.append(int(payload[ii : ii + 2], 16))
    return bytes(out)

def bytes_to_int(value):
    ret = 0
    for each in value:
        ret <<= 8
        ret += each
    return ret

def bytes_to_ip(value):
    value = [ str(each) for each in value ]
    return '.'.join(value)

def bytes_to_mac(value):
    value = [ hex(each)[2:].rjust(2, '0') for each in value ]
    return ':'.join(value)

def bytes_to_hex(value):
    return ''.join([ hex(each)[2:].rjust(2, '0').upper() for each in value ])

# Network Access Layer
# https://en.wikipedia.org/wiki/Ethernet_frame#Ethernet_II
class Ethernet2Parser():
    def __init__(self, payload):
        if not type(payload) is bytes:
            raise TypeError('payload must be bytes not {}'.format(type(payload)))
        else:
            self.payload = payload
            # 6 bytes
            self.destination_mac_address = self.payload[0:6]
            # 6 bytes
            self.source_mac_address = self.payload[6:12]
            # 2 bytes
            self.ether_type = bytes_to_int(self.payload[12:14])
            if self.ether_type == 0x0800:
                self.IPv4 = IPv4(self, 14)

    def dump_dict(self):
        ret = {}
        ret['Mac Header'] = {}
        ret['Mac Header']['Destination MAC Address'] = bytes_to_mac(self.destination_mac_address)
        ret['Mac Header']['Source MAC Address'] = bytes_to_mac(self.source_mac_address)
        ret['Mac Header']['Ether Type'] = '0x' + hex(self.ether_type)[2:].rjust(4, '0')
        if self.ether_type == 0x0800:
            ret['IPv4'] = self.IPv4.dump_dict()
        return ret

# Internet Layer
# https://en.wikipedia.org/wiki/IPv4
class IPv4:
    def __init__(self, upper_layer, start):
        self.payload = upper_layer.payload
        self.start = start
        # 4 bits
        self.version = self.payload[start] >> 4
        # 4 bits
        self.IHL = self.payload[start] & 15
        # 6 bits
        self.DSCP = self.payload[start + 1] >> 2
        # 2 bits
        self.ECN = self.payload[start + 1] & 3
        # 16 bits
        self.total_length = bytes_to_int(self.payload[start + 2:start + 4])
        # 16 bits
        self.identification = bytes_to_int(self.payload[start + 4:start + 6])
        # 3 bits
        self.flags = self.payload[start + 6] >> 5
        # 13 bits
        self.fragment_offset = bytes_to_int(bytes([self.payload[start + 6] & 31, self.payload[start + 7]]))
        # 8 bits
        self.time_to_live = self.payload[start + 8]
        # 8 bits
        self.protocol = self.payload[start + 9]
        # 16 bits
        self.header_checksum = hex(bytes_to_int(self.payload[start + 10:start + 12]))
        # 32 bits
        self.source_ip_address = bytes_to_ip(self.payload[start + 12:start + 16])
        # 32 bits
        self.destination_ip_address = bytes_to_ip(self.payload[start + 16:start + 20])
        if self.protocol == 1:
            self.ICMP = ICMP(self, self.start + 20)
        elif self.protocol == 6:
            self.TCP = TCP(self, self.start + 20)
        elif self.protocol == 17:
            self.UDP = UDP(self, self.start + 20)

    def dump_dict(self):
        ret = {}
        ret['Version'] = self.version
        ret['Internet Header Length'] = self.IHL
        ret['Differentiated Services Code Point'] = self.DSCP
        ret['Explicit Congestion Notification'] = self.ECN
        ret['Total Length'] = self.total_length
        ret['Identification'] = self.identification
        ret['Flags'] = self.flags
        ret['Fragment Offset'] = self.fragment_offset
        ret['Time To Live'] = self.time_to_live
        ret['Protocol'] = self.protocol
        ret['Header Checksum'] = self.header_checksum
        ret['Source IP Address'] = self.source_ip_address
        ret['Destination IP Address'] = self.destination_ip_address
        if self.protocol == 1:
            ret['ICMP'] = self.ICMP.dump_dict()
        elif self.protocol == 6:
            ret['TCP'] = self.TCP.dump_dict()
        elif self.protocol == 17:
            ret['UDP'] = self.UDP.dump_dict()
        return ret

# ICMP
# https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol
class ICMP:
    def __init__(self, upper_layer, start):
        self.payload = upper_layer.payload
        self.type = self.payload[start]
        self.code = self.payload[start + 1]
        self.checksum = bytes_to_int(self.payload[start + 2:start + 4])
        if self.type == 5:
            pass
        elif self.type == 11:
            pass
        elif self.type == 13:
            pass
        elif self.type == 14:
            pass
        elif self.type == 17:
            pass
        elif self.type == 18:
            pass
        elif self.type == 3:
            self.unused = self.payload[start + 4:start + 8]
            self.IPv4 = IPv4(self, start + 8)
    def dump_dict(self):
        ret = {}
        ret['Type'] = self.type
        ret['Code'] = self.code
        ret['Checksum'] = hex(self.checksum)
        if self.type == 5:
            pass
        elif self.type == 11:
            pass
        elif self.type == 13:
            pass
        elif self.type == 14:
            pass
        elif self.type == 17:
            pass
        elif self.type == 18:
            pass
        elif self.type == 3:
            ret['unused'] = bytes_to_hex(self.unused)
            ret['IPv4'] = self.IPv4.dump_dict()
        return ret

# TCP
# https://en.wikipedia.org/wiki/Transmission_Control_Protocol
class TCP:
    def __init__(self, upper_layer, start):
        self.payload = upper_layer.payload
        # 16 bits
        self.source_port = bytes_to_int(self.payload[start:start + 2])
        # 16 bits
        self.destination_port = bytes_to_int(self.payload[start + 2:start + 4])
        # 32 bits
        self.sequence_number = hex(bytes_to_int(self.payload[start + 4:start + 8]))
        # 32 bits
        self.acknowledgement_number = hex(bytes_to_int(self.payload[start + 8:start + 12]))
        # 4 bits
        self.data_offset = self.payload[start + 12] >> 4
        # 3 bits
        self.reserved = (self.payload[start + 12] >> 1) & 7
        # 1 bit
        self.NS = self.payload[start + 12] & 1
        # 1 bit
        self.CWR = (self.payload[start + 13] >> 7) & 1
        # 1 bit
        self.ECE = (self.payload[start + 13] >> 6) & 1
        # 1 bit
        self.URG = (self.payload[start + 13] >> 5) & 1
        # 1 bit
        self.ACK = (self.payload[start + 13] >> 4) & 1
        # 1 bit
        self.PSH = (self.payload[start + 13] >> 3) & 1
        # 1 bit
        self.RST = (self.payload[start + 13] >> 2) & 1
        # 1 bit
        self.SYN = (self.payload[start + 13] >> 1) & 1
        # 1 bit
        self.FIN = self.payload[start + 13] & 1
        # 16 bits
        self.window_size = bytes_to_int(self.payload[start + 14:start + 16])
        # 16 bits
        self.checksum = bytes_to_int(self.payload[start + 16:start + 18])
        # 16 bits
        self.urgent_pointer = bytes_to_int(self.payload[start + 18:start + 20])
        if self.data_offset > 5:
            self.tcp_options = []
            idx = start + 20
            while idx < len(self.payload) and idx < start + self.data_offset * 4:
                #
                if self.payload[idx] == 0:
                    break
                elif self.payload[idx] == 1:
                    idx += 1
                elif self.payload[idx] == 2:
                    tmp = {}
                    tmp['kind'] = self.payload[idx]
                    tmp['length'] = self.payload[idx + 1]
                    tmp['MSS Value'] = bytes_to_int(self.payload[idx + 2:idx + 4])
                    idx += 4
                    self.tcp_options.append(tmp)
                elif self.payload[idx] == 3:
                    tmp = {}
                    tmp['kind'] = self.payload[idx]
                    tmp['length'] = self.payload[idx + 1]
                    tmp['Shift count'] = self.payload[idx + 2]
                    idx += 3
                    self.tcp_options.append(tmp)
                elif self.payload[idx] == 4:
                    tmp = {}
                    tmp['kind'] = self.payload[idx]
                    tmp['length'] = self.payload[idx + 1]
                    idx += 2
                    self.tcp_options.append(tmp)
                elif self.payload[idx] == 5:
                    tmp = {}
                    tmp['kind'] = self.payload[idx]
                    tmp['length'] = self.payload[idx + 1]
                    for number, plus in enumerate(range(2, tmp['length'], 8), start = 1):
                        tmp['left edge{}'.format(number)] = bytes_to_int(self.payload[idx + plus:idx + plus + 4])
                        tmp['right edge{}'.format(number)] = bytes_to_int(self.payload[idx + plus + 4:idx + plus + 8])
                    idx += tmp['length']
                    self.tcp_options.append(tmp)
                elif self.payload[idx] == 8:
                    tmp = {}
                    tmp['kind'] = self.payload[idx]
                    tmp['length'] = self.payload[idx + 1]
                    tmp['Timestamp value'] = bytes_to_int(self.payload[idx + 2:idx + 6])
                    tmp['Timestamp echo reply'] = bytes_to_int(self.payload[idx + 6:idx + 10])
                    idx += 10
                    self.tcp_options.append(tmp)
                # not implemented
                elif self.payload[idx] == 30:
                    if self.payload[idx + 1] == 18:
                        idx += 20
                    else:
                        idx += self.payload[idx + 1]
            if start + self.data_offset * 4 < len(self.payload):
                self.tcp_payload = self.payload[start + self.data_offset * 4:upper_layer.start + upper_layer.total_length]
            else:
                self.tcp_payload = []
        else:
            if start + 20 < len(self.payload):
                self.tcp_payload = self.payload[start + 20:upper_layer.start + upper_layer.total_length]
            else:
                self.tcp_payload = []


    def dump_dict(self):
        ret = {}
        ret['Source port'] = self.source_port
        ret['Destination port'] = self.destination_port
        ret['Sequence number'] = self.sequence_number
        ret['Acknowledgment number'] = self.acknowledgement_number
        ret['Data offset'] = self.data_offset
        ret['Reserved'] = self.reserved
        ret['Flags'] = {}
        ret['Flags']['NS'] = self.NS
        ret['Flags']['CWR'] = self.CWR
        ret['Flags']['ECE '] = self.ECE
        ret['Flags']['URG'] = self.URG
        ret['Flags']['ACK'] = self.ACK
        ret['Flags']['PSH'] = self.PSH
        ret['Flags']['RST'] = self.RST
        ret['Flags']['SYN'] = self.SYN
        ret['Flags']['FIN'] = self.FIN
        ret['Window size'] = self.window_size
        ret['Checksum'] = hex(self.checksum)
        ret['Urgent pointer'] = self.urgent_pointer
        try:
            ret['String Payload'] = str(self.tcp_payload)
        except:
            pass
        ret['Hex Payload'] = bytes_to_hex(self.tcp_payload)
        if self.data_offset > 5:
            ret['Options'] = self.tcp_options
        return ret

# UDP
# https://en.wikipedia.org/wiki/User_Datagram_Protocol
class UDP:
    def __init__(self, upper_layer, start):
        self.payload = upper_layer.payload
        self.start = start
        # 16 bits
        self.source_port = bytes_to_int(self.payload[start:start + 2])
        # 16 bits
        self.destination_port = bytes_to_int(self.payload[start + 2:start + 4])
        # 16 bits
        self.length = bytes_to_int(self.payload[start + 4:start + 6])
        # 16 bits
        self.checksum = bytes_to_int(self.payload[start + 6:start + 8])
        self.udp_payload = self.payload[start + 8:start + upper_layer.total_length]

    def dump_dict(self):
        ret = {}
        ret['Source port'] = self.source_port
        ret['Destination port'] = self.destination_port
        ret['Length'] = self.length
        ret['Checksum'] = hex(self.checksum)
        try:
            ret['String Payload'] = str(self.udp_payload)
        except:
            pass
        ret['Hex Payload'] = bytes_to_hex(self.udp_payload)
        return ret
