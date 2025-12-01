-- Snort3 Configuration for Dual-Engine Testing
-- Tests both Snort3 packet-level and SnortSharp flow-level detection

---------------------------------------------------------------------------
-- Setup environment
---------------------------------------------------------------------------

-- Set paths
HOME_NET = 'any'
EXTERNAL_NET = 'any'

include 'snort3/lua/snort_defaults.lua'

---------------------------------------------------------------------------
-- Configure basic Snort3 settings
---------------------------------------------------------------------------

-- Configure outputs
alert_fast = {
    file = true,
    packet = false,
    limit = 1000,
}

-- Configure logging
output = {
    logdir = '.',
}

---------------------------------------------------------------------------
-- Network analysis
---------------------------------------------------------------------------

stream = { }

stream_tcp = {
    policy = 'bsd',
}

stream_ip = { }

stream_icmp = { }

stream_udp = { }

---------------------------------------------------------------------------
-- Detection configuration
---------------------------------------------------------------------------

ips = {
    enable_builtin_rules = true,
    variables = default_variables,
    rules = [[
        include $RULE_PATH/local.rules
        include $RULE_PATH/unsw_packet_rules.rules
    ]]
}

---------------------------------------------------------------------------
-- Configure DAQ for PCAP replay
---------------------------------------------------------------------------

daq = {
    inputs = { "PCAP_FILE_PLACEHOLDER" },
    snaplen = 1518,
    module_dirs = { '/usr/local/lib/daq' },
    modules = {
        {
            name = 'pcap',
            mode = 'read-file',
        }
    }
}

---------------------------------------------------------------------------
-- Normalizations and preprocessing
---------------------------------------------------------------------------

normalizer = {
    tcp = {
        ips = true,
    }
}

---------------------------------------------------------------------------
-- Port scan detection (will catch reconnaissance)
---------------------------------------------------------------------------

port_scan = {
    tcp_window = 10,
    tcp_limit = 10,
    udp_window = 10,
    udp_limit = 10,
}

---------------------------------------------------------------------------
-- Performance monitoring
---------------------------------------------------------------------------

perf_monitor = {
    base = true,
    flow = true,
    packets = 1000,
}
