-- Snort3 configuration for UNSW-NB15 testing

-- Define network variables
HOME_NET = 'any'
EXTERNAL_NET = 'any'

-- Define server variables (these are networks, not paths!)
DNS_SERVERS = HOME_NET
SMTP_SERVERS = HOME_NET
HTTP_SERVERS = HOME_NET
SQL_SERVERS = HOME_NET
TELNET_SERVERS = HOME_NET
SSH_SERVERS = HOME_NET
FTP_SERVERS = HOME_NET
SIP_SERVERS = HOME_NET

-- Define port variables
HTTP_PORTS = 'any'
FTP_PORTS = 'any'
SIP_PORTS = 'any'
SHELLCODE_PORTS = 'any'
ORACLE_PORTS = 'any'
SSH_PORTS = 'any'
FILE_DATA_PORTS = 'any'

-- Make variables available to rules (following snort_defaults.lua format)
default_variables =
{
    nets =
    {
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
    },

    ports =
    {
        HTTP_PORTS = HTTP_PORTS,
        FTP_PORTS = FTP_PORTS,
        SIP_PORTS = SIP_PORTS,
        SHELLCODE_PORTS = SHELLCODE_PORTS,
        ORACLE_PORTS = ORACLE_PORTS,
        SSH_PORTS = SSH_PORTS,
        FILE_DATA_PORTS = FILE_DATA_PORTS,
    }
}

-- IPS configuration
ips =
{
    mode = 'inline',
    variables = default_variables,

    -- Load community rules
    rules = [[
        include snort3-community-rules/snort3-community.rules
    ]]
}

-- Alert output (CSV format for easy parsing)
alert_csv =
{
    file = true,
    fields = 'timestamp pkt_num proto pkt_gen pkt_len dir src_ap dst_ap rule action',
    limit = 0,
    separator = ',',
}

-- Stream configuration
stream = { }

stream_tcp =
{
    policy = 'first'
}

stream_udp = { }

stream_ip = { }

-- Network analysis
network = { }

-- Normalizer
normalizer = { }

-- Search engine
search_engine = { }

-- Protocol inspectors
binder =
{
    {
        when = { proto = 'tcp' },
        use = { type = 'stream_tcp' }
    },
    {
        when = { proto = 'udp' },
        use = { type = 'stream_udp' }
    }
}
