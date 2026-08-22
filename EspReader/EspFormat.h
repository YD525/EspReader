#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>

#pragma pack(push, 1)
struct RecordHeader
{
    char Sig[4];
    std::uint32_t DataSize;
    std::uint32_t Flags;
    std::uint32_t FormID;
    std::uint32_t VersionCtrl;
    std::uint16_t Version;
    std::uint16_t Unknown;
};

struct GroupHeader
{
    char Sig[4];
    std::uint32_t Size;
    char Label[4];
    std::uint32_t GroupType;
    std::uint32_t Stamp;
    std::uint32_t Unknown;
};

struct SubRecordHeader
{
    char Sig[4];
    std::uint16_t Size;
};
#pragma pack(pop)

constexpr std::uint32_t RecordFlagCompressed = 0x00040000;
constexpr std::uint32_t Tes4FlagLocalized = 0x00000080;
constexpr std::size_t MaxRecordDataSize = 256ULL * 1024ULL * 1024ULL;
constexpr std::size_t MaxDecompressedRecordSize = 512ULL * 1024ULL * 1024ULL;
constexpr std::size_t MaxSubRecordDataSize = 256ULL * 1024ULL * 1024ULL;
constexpr std::uint32_t MaxGroupDepth = 128;

inline bool IsGroupSignature(const char signature[4]) noexcept
{
    return std::memcmp(signature, "GRUP", 4) == 0;
}

inline bool IsCompressed(const RecordHeader& header) noexcept
{
    return (header.Flags & RecordFlagCompressed) != 0;
}
