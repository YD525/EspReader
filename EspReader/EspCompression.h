#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

bool ZlibDecompress(
    const std::uint8_t* source,
    std::size_t sourceSize,
    std::vector<std::uint8_t>& output,
    std::size_t uncompressedSize);

bool ZlibCompress(
    const std::uint8_t* source,
    std::size_t sourceSize,
    std::vector<std::uint8_t>& output);
