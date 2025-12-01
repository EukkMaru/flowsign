//--------------------------------------------------------------------------
// Copyright (C) 2024 - FlowSign Project
// Linux Cooked Capture (SLL) codec for Snort3
//--------------------------------------------------------------------------

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <daq_dlt.h>
#include <arpa/inet.h>

#include "codecs/codec_module.h"
#include "framework/codec.h"
#include "log/log_text.h"
#include "main/snort_config.h"
#include "protocols/packet_manager.h"

using namespace snort;

#define CD_LINUX_SLL_NAME "linux_sll"
#define CD_LINUX_SLL_HELP_STR "support for Linux cooked capture protocol"
#define LINUX_SLL_HDR_LEN 16
#define DLT_LINUX_SLL 113

namespace
{
static const RuleMap linux_sll_rules[] =
{
    { DECODE_BAD_LINUX_SLL, "truncated linux cooked header" },
    { 0, nullptr }
};

class LinuxSLLModule : public BaseCodecModule
{
public:
    LinuxSLLModule() : BaseCodecModule(CD_LINUX_SLL_NAME, CD_LINUX_SLL_HELP_STR) { }

    const RuleMap* get_rules() const override
    { return linux_sll_rules; }
};

class LinuxSLLCodec : public Codec
{
public:
    LinuxSLLCodec() : Codec(CD_LINUX_SLL_NAME) { }

    void get_protocol_ids(std::vector<ProtocolId>&) override;
    void get_data_link_type(std::vector<int>&) override;
    bool decode(const RawData&, CodecData&, DecodeData&) override;
};
} // namespace

void LinuxSLLCodec::get_data_link_type(std::vector<int>& v)
{
    v.emplace_back(DLT_LINUX_SLL);
}

void LinuxSLLCodec::get_protocol_ids(std::vector<ProtocolId>& v)
{
    v.emplace_back(ProtocolId::LINUX_SLL);
}

bool LinuxSLLCodec::decode(const RawData& raw, CodecData& codec, DecodeData&)
{
    // Linux cooked header is 16 bytes
    if (raw.len < LINUX_SLL_HDR_LEN)
    {
        codec_event(codec, DECODE_BAD_LINUX_SLL);
        return false;
    }

    // Parse Linux SLL header structure:
    // Offset  Length  Description
    // 0       2       Packet type
    // 2       2       ARPHRD_ type
    // 4       2       Link-layer address length
    // 6       8       Link-layer address (padded)
    // 14      2       Protocol type (e.g., 0x0800 for IPv4)

    const uint8_t* sll_hdr = raw.data;
    uint16_t protocol = (sll_hdr[14] << 8) | sll_hdr[15];  // Big-endian

    // Set layer length to Linux SLL header size
    codec.lyr_len = LINUX_SLL_HDR_LEN;

    // Determine next protocol based on EtherType
    switch (protocol)
    {
        case 0x0800:  // IPv4
            codec.next_prot_id = ProtocolId::ETHERTYPE_IPV4;
            break;
        case 0x86DD:  // IPv6
            codec.next_prot_id = ProtocolId::ETHERTYPE_IPV6;
            break;
        case 0x0806:  // ARP
            codec.next_prot_id = ProtocolId::ETHERTYPE_ARP;
            break;
        case 0x8100:  // 802.1Q VLAN
            codec.next_prot_id = ProtocolId::ETHERTYPE_8021Q;
            break;
        default:
            // Unknown protocol
            codec.next_prot_id = ProtocolId::FINISHED_DECODE;
            break;
    }

    codec.proto_bits |= PROTO_BIT__ETH;  // Mark as link layer processed
    return true;
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Codec* ctor(Module*)
{ return new LinuxSLLCodec(); }

static void dtor(Codec* cd)
{ delete cd; }

static const CodecApi linux_sll_api =
{
    {
        PT_CODEC,
        sizeof(CodecApi),
        CDAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        CD_LINUX_SLL_NAME,
        CD_LINUX_SLL_HELP_STR,
        nullptr,
        nullptr
    },
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor,
    dtor,
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* cd_linux_sll[] =
#endif
{
    &linux_sll_api.base,
    nullptr
};
