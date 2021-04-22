import ipaddress

THRESHOLD = 1

def find_server(d, sip, dip, sport, dport):
    if sport <= 1024 and dport > 1024:
        return 1
    elif sport > 1024 and dport <= 1024:
        return -1
    server = 0
    sport_count = d['ip'][sip][sport]
    dport_count = d['ip'][dip][dport]
    if sport_count > dport_count:
        server += 1
    elif sport_count < dport_count:
        server -= 1
    if len(d['ip'][sip]) > len(d['ip'][dip]):
        server -= 1
    elif len(d['ip'][sip]) < len(d['ip'][dip]):
        server += 1
    temp = sport_count / sum(d['ip'][sip].values()) - dport_count / sum(d['ip'][dip].values())
    server += temp//abs(temp)
    return server

def set_threshold(d):
    global THRESHOLD
    card_len_list = [len(i[1]) for i in d['network'].items()]
    card_len_list.sort(reverse=True)
    
    for idx, card_len in enumerate(card_len_list):
        if card_len <= idx:
            THRESHOLD = card_len
            break

def separate(parsed, d):
    global THRESHOLD
    if parsed != -1:
        sip, dip, sport, dport = parsed
        sn = ipaddress.ip_interface(sip + '/16').network
        dn = ipaddress.ip_interface(dip + '/16').network
        sn_oppo_card = len(d['network'][sn])
        dn_oppo_card = len(d['network'][dn])

        # if source is inner
        if sn_oppo_card > THRESHOLD and dn_oppo_card <= THRESHOLD:
            s_is_server = find_server(d, sip, dip, sport, dport)
            # if source is server
            if s_is_server > 0:
                return 0
            elif s_is_server < 0:
                return 1
            # can't separate server : client
            else:
                return 4
        # if source is outer
        elif sn_oppo_card <= THRESHOLD and dn_oppo_card > THRESHOLD:
            s_is_server = find_server(d, sip, dip, sport, dport)
            # if source is server
            if s_is_server > 0:
                return 2
            elif s_is_server < 0:
                return 3
            # can't separate server : client
            else:
                return 4
        # can't separate inner : outer
        else:
            return 5
    else:
        return 6
