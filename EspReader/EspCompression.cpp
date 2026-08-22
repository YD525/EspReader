#include "EspCompression.h"

#include <limits>

#include "miniz.h"

namespace
{
    constexpr std::size_t MaxDecompressedRecordSize = 512ULL * 1024ULL * 1024ULL;
}

bool ZlibDecompress(
    const std::uint8_t* source,
    std::size_t sourceSize,
    std::vector<std::uint8_t>& output,
    std::size_t uncompressedSize)
{
    if (uncompressedSize > MaxDecompressedRecordSize || (sourceSize != 0 && source == nullptr))
        return false;

    output.resize(uncompressedSize);
    const std::size_t result = tinfl_decompress_mem_to_mem(
        output.data(),
        uncompressedSize,
        source,
        sourceSize,
        TINFL_FLAG_PARSE_ZLIB_HEADER);
    return result == uncompressedSize;
}

bool ZlibCompress(
    const std::uint8_t* source,
    std::size_t sourceSize,
    std::vector<std::uint8_t>& output)
{
    if (sourceSize > static_cast<std::size_t>((std::numeric_limits<mz_ulong>::max)()))
        return false;

    const mz_ulong sourceLength = static_cast<mz_ulong>(sourceSize);
    mz_ulong destinationLength = compressBound(sourceLength);
    output.resize(destinationLength);
    const int result = compress2(
        output.data(),
        &destinationLength,
        source,
        sourceLength,
        Z_BEST_COMPRESSION);
    if (result != Z_OK)
        return false;

    output.resize(destinationLength);
    return true;
}
