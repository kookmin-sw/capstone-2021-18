from payload_parser import bytes_to_int, to_byte, bytes_to_ip
import ipaddress
import pickle
from tqdm import tqdm
import os

def update(d, sip, sport, dip, dport):
    sn = ipaddress.ip_interface(sip + '/16').network
    dn = ipaddress.ip_interface(dip + '/16').network
    if sn in d['network']:
        if dn in d['network'][sn]:
            d['network'][sn][dn] += 1
        else:
            d['network'][sn][dn] = 1
        if sip in d['ip']:
            if sport in d['ip'][sip]:
                d['ip'][sip][sport] += 1
            else:
                d['ip'][sip][sport] = 1
        else:
            d['ip'][sip] = {sport:1}
    else:
        d['network'][sn] = {dn:1}
        d['ip'][sip] = {sport:1}
    if dn in d['network']:
        if sn in d['network'][dn]:
            d['network'][dn][sn] += 1
        else:
            d['network'][dn][sn] = 1
        if dip in d['ip']:
            if dport in d['ip'][dip]:
                d['ip'][dip][dport] += 1
            else:
                d['ip'][dip][dport] = 1
        else:
            d['ip'][dip] = {dport:1}
    else:
        d['network'][dn] = {sn:1}
        d['ip'][dip] = {dport:1}

def parse_ip_port(p):
    payload = p[-1]
    protocol = bytes_to_int(to_byte(payload[46:48]))
    flag = 1
    if protocol == 6:
        p_type = 'TCP'
    elif protocol == 17:
        p_type = 'UDP'
    else:
        flag = 0
    if flag:
        sip = bytes_to_ip(to_byte(payload[52:60]))
        dip = bytes_to_ip(to_byte(payload[60:68]))
        sport = bytes_to_int(to_byte(payload[68:72]))
        dport = bytes_to_int(to_byte(payload[72:76]))
        protocol = bytes_to_int(to_byte(payload[46:48]))
        return sip, dip, sport, dport
    return -1

def preprocess(p, d):
    parsed = parse_ip_port(p)
    if parsed != -1:
        sip, dip, sport, dport = parsed
        update(d, sip, sport, dip, dport)
