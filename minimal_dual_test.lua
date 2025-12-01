-- Minimal Snort3 Configuration for Dual-Engine Testing

HOME_NET = 'any'
EXTERNAL_NET = 'any'

-- Basic network processing
stream = { }
stream_tcp = { policy = 'bsd' }
stream_ip = { }
stream_icmp = { }
stream_udp = { }

-- Basic normalization
normalizer = {
    tcp = { ips = true }
}

-- Enable detection with embedded rules
ips = {
    enable_builtin_rules = false,
    variables = { HOME_NET = HOME_NET, EXTERNAL_NET = EXTERNAL_NET },
}

-- Alert output
alert_fast = {
    file = true,
    packet = false,
}

-- Performance monitoring
perf_monitor = {
    base = true,
    flow = true,
}
