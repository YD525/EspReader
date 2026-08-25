#pragma once

#include <cstddef>
#include <cstdint>
#include <fstream>
#include <memory>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include "EspRecord.cpp"

constexpr int RESULT_OK = 1;
constexpr int RESULT_NOT_FOUND = 0;
constexpr int RESULT_NOT_INITIALIZED = -1;
constexpr int RESULT_ERROR = -2;


class EspBinaryReader;

// Owns a completed parse result. Callers can inspect the model as read-only data or transfer
// its components into the mutation layer after parsing has succeeded.
class EspParsedDocument final
{
public:
    EspParsedDocument(EspParsedDocument&&) noexcept = default;
    EspParsedDocument& operator=(EspParsedDocument&&) noexcept = default;
    EspParsedDocument(const EspParsedDocument&) = delete;
    EspParsedDocument& operator=(const EspParsedDocument&) = delete;

    const EspData& Data() const noexcept;
    const CharacterTracker& Characters() const noexcept;
    const ESP_HeuristicAnalysis& Analysis() const noexcept;
    bool IsLocalized() const noexcept;

    std::unique_ptr<EspData> TakeData() noexcept;
    std::unique_ptr<CharacterTracker> TakeCharacters() noexcept;
    std::unique_ptr<ESP_HeuristicAnalysis> TakeAnalysis() noexcept;

private:
    friend class EspParser;

    EspParsedDocument();

    std::unique_ptr<EspData> _data;
    std::unique_ptr<CharacterTracker> _characters;
    std::unique_ptr<ESP_HeuristicAnalysis> _analysis;
    bool _isLocalized = false;
};

class EspParser final
{
public:
    // Parses one complete plugin and throws std::runtime_error when its binary format is invalid.
    static EspParsedDocument Parse(std::ifstream& stream, const RecordFilter& filter);
    static EspParsedDocument Parse(
        const std::uint8_t* data,
        std::size_t size,
        const RecordFilter& filter);

private:
    static EspParsedDocument Parse(EspBinaryReader& reader, const RecordFilter& filter);
    EspParser() = delete;
};
