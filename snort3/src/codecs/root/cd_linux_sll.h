//--------------------------------------------------------------------------
// Copyright (C) 2024 - FlowSign Project
// Linux Cooked Capture (SLL) codec for Snort3
//--------------------------------------------------------------------------

#ifndef CODECS_CD_LINUX_SLL_H
#define CODECS_CD_LINUX_SLL_H

#include "framework/codec.h"

namespace snort
{
struct LinuxSLLHdr
{
    uint16_t packet_type;     // Packet type (0=to us, 1=broadcast, 2=multicast, 3=to someone else, 4=from us)
    uint16_t arphrd_type;     // ARPHRD_ type
    uint16_t ll_addr_len;     // Link-layer address length
    uint8_t ll_addr[8];       // Link-layer address (padded to 8 bytes)
    uint16_t protocol;        // Protocol type (e.g., 0x0800 for IPv4, 0x86DD for IPv6)
};

class LinuxSLLCodec : public Codec
{
public:
    LinuxSLLCodec() : Codec("linux_sll") { }

    void get_protocol_ids(std::vector<ProtocolId>&) override;
    bool decode(const RawData&, CodecData&, DecodeData&) override;
};
} // namespace snort
#endif
