#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <limits>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <vector>

class EspBinaryReader
{
public:
    static constexpr std::uint64_t MaxFileSize = 4ULL * 1024ULL * 1024ULL * 1024ULL;

    explicit EspBinaryReader(std::ifstream& stream)
        : _stream(&stream), _data(nullptr), _size(0), _position(0), _failed(false)
    {
        stream.seekg(0, std::ios::end);
        const std::streampos end = stream.tellg();
        if (end < 0)
            throw std::runtime_error("Unable to determine the plugin file size.");

        _size = static_cast<std::uint64_t>(end);
        if (_size > MaxFileSize)
            throw std::runtime_error("Plugin file exceeds the configured size limit.");

        stream.seekg(0, std::ios::beg);
        if (!stream)
            throw std::runtime_error("Unable to seek to the start of the plugin file.");
    }

    EspBinaryReader(const std::uint8_t* data, std::size_t size)
        : _stream(nullptr), _data(data), _size(size), _position(0), _failed(false)
    {
        if (size != 0 && data == nullptr)
            throw std::invalid_argument("A non-empty plugin byte range requires data.");
    }

    [[nodiscard]] std::uint64_t Position() const noexcept
    {
        return _position;
    }

    [[nodiscard]] std::uint64_t Size() const noexcept
    {
        return _size;
    }

    [[nodiscard]] std::uint64_t Remaining() const noexcept
    {
        return _size - _position;
    }

    [[nodiscard]] bool Failed() const noexcept
    {
        return _failed;
    }

    void Read(void* destination, std::size_t byteCount, const char* context)
    {
        Require(byteCount, context);
        if (byteCount == 0)
            return;
        if (destination == nullptr)
            Fail(std::string(context) + " has no destination buffer.");

        if (_stream != nullptr)
        {
            if (byteCount > static_cast<std::size_t>((std::numeric_limits<std::streamsize>::max)()))
                Fail(std::string(context) + " exceeds the stream read limit.");

            _stream->read(static_cast<char*>(destination), static_cast<std::streamsize>(byteCount));
            if (_stream->gcount() != static_cast<std::streamsize>(byteCount) || !*_stream)
                Fail(std::string(context) + " could not be read completely.");
        }
        else
        {
            std::memcpy(destination, _data + _position, byteCount);
        }

        _position += byteCount;
    }

    template<typename T>
    T ReadValue(const char* context)
    {
        static_assert(std::is_trivially_copyable<T>::value, "Binary values must be trivially copyable.");
        T value{};
        Read(&value, sizeof(value), context);
        return value;
    }

    std::vector<std::uint8_t> ReadBytes(
        std::size_t byteCount,
        std::size_t maximumByteCount,
        const char* context)
    {
        if (byteCount > maximumByteCount)
            Fail(std::string(context) + " exceeds the configured allocation limit.");

        Require(byteCount, context);
        std::vector<std::uint8_t> bytes(byteCount);
        Read(bytes.data(), bytes.size(), context);
        return bytes;
    }

    void Skip(std::uint64_t byteCount, const char* context)
    {
        Require(byteCount, context);
        if (_stream != nullptr)
        {
            if (byteCount > static_cast<std::uint64_t>((std::numeric_limits<std::streamoff>::max)()))
                Fail(std::string(context) + " exceeds the stream seek limit.");

            _stream->seekg(static_cast<std::streamoff>(byteCount), std::ios::cur);
            if (!*_stream)
                Fail(std::string(context) + " could not be skipped completely.");
        }

        _position += byteCount;
    }

    std::uint64_t SubrangeEnd(
        std::uint64_t byteCount,
        std::uint64_t outerEnd,
        const char* context)
    {
        if (outerEnd > _size || _position > outerEnd || byteCount > outerEnd - _position)
            Fail(std::string(context) + " exceeds its containing byte range.");

        return _position + byteCount;
    }

    void RequireWithin(std::uint64_t end, std::uint64_t byteCount, const char* context)
    {
        if (end > _size || _position > end || byteCount > end - _position)
            Fail(std::string(context) + " exceeds its containing byte range.");
    }

    void RequireEnd(std::uint64_t end, const char* context)
    {
        if (_position != end)
            Fail(std::string(context) + " was not consumed exactly.");
    }

    [[noreturn]] void Reject(const std::string& message)
    {
        Fail(message);
    }

private:
    void Require(std::uint64_t byteCount, const char* context)
    {
        if (byteCount > Remaining())
            Fail(std::string(context) + " exceeds the remaining plugin input.");
    }

    [[noreturn]] void Fail(const std::string& message)
    {
        _failed = true;
        throw std::runtime_error(message);
    }

    std::ifstream* _stream;
    const std::uint8_t* _data;
    std::uint64_t _size;
    std::uint64_t _position;
    bool _failed;
};
