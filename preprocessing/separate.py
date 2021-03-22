import ipaddress

def find_server(d, sip, dip, sport, dport):
    if sport <= 1024 and dport > 1024:
        return 1
    elif sport > 1024 and dport <= 1024:
        return -1
    server = 0
    if d['ip'][sip][sport]>d['ip'][dip][dport]:
        server += 1
    elif d['ip'][sip][sport]<d['ip'][dip][dport]:
        server -= 1
    if len(d['ip'][sip])>len(d['ip'][dip]):
        server -= 1
    elif len(d['ip'][sip])<len(d['ip'][dip]):
        server += 1
    if (d['ip'][sip][sport]/sum(d['ip'][sip].values()) >
				d['ip'][dip][dport]/sum(d['ip'][dip].values())):
        server += 1
    elif (d['ip'][sip][sport]/sum(d['ip'][sip].values()) <
					d['ip'][dip][dport]/sum(d['ip'][dip].values())):
        server -= 1
    return server

def separate(parsed, d):
    if parsed != -1:
        sip, dip, sport, dport = parsed
        sn = ipaddress.ip_interface(sip + '/16').network
        dn = ipaddress.ip_interface(dip + '/16').network
        sn_oppo_card = len(d['network'][sn])
        dn_oppo_card = len(d['network'][dn])
        # if source is inner
        if sn_oppo_card >= 18 and dn_oppo_card < 18:
            s_is_server = find_server(d, sip, dip, sport, dport)
            # if source is server
            if s_is_server:
                return 0
            elif not s_is_server:
                return 1
            # can't separate server : client
            else:
                return 4
        # if source is outer
        elif sn_oppo_card < 18 and dn_oppo_card >= 18:
            s_is_server = find_server(d, sip, dip, sport, dport)
            # if source is server
            if s_is_server:
                return 2
            elif not s_is_server:
                return 3
            # can't separate server : client
            else:
                return 4
        # can't separate inner : outer
        else:
            return 5
    else:
        return 6