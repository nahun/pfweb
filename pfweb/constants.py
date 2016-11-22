from pf.constants import *

"""pfweb constants used in the templates"""

# Port ops dict
# List:
#   0: Sort options in HTML select
#   1: Description
#   2: str.format syntax
PFWEB_PORT_OPS = {
    PF_OP_NONE: [0, "Any", "*"],
    PF_OP_EQ:   [1, "Equal =", "{0[0]}"],
    PF_OP_RRG:  [2, "Inclusive Range :", "{0[0]}:{0[1]}"],
    PF_OP_IRG:  [3, "Range ><", "{0[0]} >< {0[1]}"],
    PF_OP_XRG:  [4, "Inverse Range <>", "{0[0]} <> {0[1]}"],
    PF_OP_NE:   [5, "Not Equal !=", "{0[0]}"],
    PF_OP_LT:   [6, "Less Than <", "{0[0]}"],
    PF_OP_LE:   [7, "Less Than or equal <=", "{0[0]}"],
    PF_OP_GT:   [8, "Greater Than >", "{0[0]}"],
    PF_OP_GE:   [9, "Greater than or equal >=", "{0[0]}"]
}

# IPv4 ICMP Types and descriptions
PFWEB_ICMP_TYPES = {
    ICMP_ECHO:              "Echo",
    ICMP_ECHOREPLY:         "Echo Reply",
    ICMP_UNREACH:           "Destination Unreachable",
    ICMP_SOURCEQUENCH:      "Source Quench",
    ICMP_REDIRECT:          "Redirect",
    ICMP_ALTHOSTADDR:       "Alternate Host Address",
    ICMP_ROUTERADVERT:      "Router Advertisement",
    ICMP_ROUTERSOLICIT:     "Router Solicitation",
    ICMP_TIMXCEED:          "Time Exceeded",
    ICMP_PARAMPROB:         "Parameter Problem",
    ICMP_TSTAMP:            "Timestamp",
    ICMP_TSTAMPREPLY:       "Timestamp Reply",
    ICMP_IREQ:              "Information Request",
    ICMP_IREQREPLY:         "Information Reply",
    ICMP_MASKREQ:           "Address Mask Request",
    ICMP_MASKREPLY:         "Address Mask Reply",
    ICMP_TRACEROUTE:        "Traceroute",
    ICMP_DATACONVERR:       "Datagram Conversion Error",
    ICMP_MOBILE_REDIRECT:   "Mobile Host Redirect ",
    ICMP_IPV6_WHEREAREYOU:  "IPv6 Where-Are-You",
    ICMP_IPV6_IAMHERE:      "IPv6 I-Am-Here",
    ICMP_MOBILE_REGREQUEST: "Mobile Registration Request",
    ICMP_MOBILE_REGREPLY:   "Mobile Registration Reply",
    ICMP_SKIP:              "SKIP",
    ICMP_PHOTURIS:          "Photuris"
}

# IPv6 ICMP Types and descriptions
PFWEB_ICMP6_TYPES = {
    ICMP6_DST_UNREACH:           "Destination Unreachable",
    ICMP6_PACKET_TOO_BIG:        "Packet Too Big",
    ICMP6_TIME_EXCEEDED:         "Time Exceeded",
    ICMP6_PARAM_PROB:            "Parameter Problem",
    ICMP6_ECHO_REQUEST:          "Echo Request",
    ICMP6_ECHO_REPLY:            "Echo Reply",
    ICMP6_MEMBERSHIP_QUERY:      "Multicast Listener Query",
    ICMP6_MEMBERSHIP_REPORT:     "Multicast Listener Report",
    ICMP6_MEMBERSHIP_REDUCTION:  "Multicast Listener Done",
    ND_ROUTER_SOLICIT:           "Router Solicitation",
    ND_ROUTER_ADVERT:            "Router Advertisement",
    ND_NEIGHBOR_SOLICIT:         "Neighbor Solicitation",
    ND_NEIGHBOR_ADVERT:          "Router Advertisement",
    ND_REDIRECT:                 "Redirect Message",
    ICMP6_ROUTER_RENUMBERING:    "Router Renumbering",
    ICMP6_WRUREQUEST:            "Who are you request",
    ICMP6_WRUREPLY:              "Who are you reply",
    ICMP6_FQDN_QUERY:            "FQDN Query",
    ICMP6_FQDN_REPLY:            "FQDN Reply",
    ICMP6_NI_QUERY:              "ICMP Node Information Query",
    ICMP6_NI_REPLY:              "ICMP Node Information Response",
    MLD_MTRACE_RESP:             "mtrace Response",
    MLD_MTRACE:                  "mtrace Messages",
}