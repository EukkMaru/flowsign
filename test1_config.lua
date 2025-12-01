HOME_NET = 'any'
EXTERNAL_NET = 'any'
DNS_SERVERS = HOME_NET
SMTP_SERVERS = HOME_NET
HTTP_SERVERS = HOME_NET
SQL_SERVERS = HOME_NET
TELNET_SERVERS = HOME_NET
SSH_SERVERS = HOME_NET
FTP_SERVERS = HOME_NET
SIP_SERVERS = HOME_NET
ORACLE_SERVERS = HOME_NET

HTTP_PORTS = 'any'
FTP_PORTS = 'any'
SSH_PORTS = 'any'
TELNET_PORTS = 'any'
FILE_DATA_PORTS = 'any'
ORACLE_PORTS = 'any'
SIP_PORTS = 'any'

default_variables = {
    nets = {
        HOME_NET = HOME_NET,
        EXTERNAL_NET = EXTERNAL_NET,
        DNS_SERVERS = DNS_SERVERS,
        SMTP_SERVERS = SMTP_SERVERS,
        HTTP_SERVERS = HTTP_SERVERS,
        SQL_SERVERS = SQL_SERVERS,
        TELNET_SERVERS = TELNET_SERVERS,
        SSH_SERVERS = SSH_SERVERS,
        FTP_SERVERS = FTP_SERVERS,
        SIP_SERVERS = SIP_SERVERS,
        ORACLE_SERVERS = ORACLE_SERVERS
    },
    ports = {
        HTTP_PORTS = HTTP_PORTS,
        FTP_PORTS = FTP_PORTS,
        SSH_PORTS = SSH_PORTS,
        TELNET_PORTS = TELNET_PORTS,
        FILE_DATA_PORTS = FILE_DATA_PORTS,
        ORACLE_PORTS = ORACLE_PORTS,
        SIP_PORTS = SIP_PORTS
    }
}

ips = {
    mode = 'inline',
    variables = default_variables,
    rules = [[ include snort3-community-rules/snort3-community.rules ]]
}

-- FlowSign inspector with EMPTY rules
snortsharp = {
    window_size = 50,
    queue_capacity = 1000,
    alert_capacity = 10000,
    rules_file = 'empty_flow_rules.txt'
}

alert_csv = {
    file = true,
    fields = 'timestamp pkt_num proto pkt_gen pkt_len dir src_ap dst_ap rule action',
    limit = 0,
    separator = ','
}

stream = { }
stream_tcp = { policy = 'first' }
stream_udp = { }
binder = {
    { when = { proto = 'tcp' }, use = { type = 'stream_tcp' } },
    { when = { proto = 'udp' }, use = { type = 'stream_udp' } }
}
