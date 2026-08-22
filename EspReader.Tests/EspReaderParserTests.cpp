#include "CppUnitTest.h"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <vector>

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace
{
    constexpr std::uint32_t CompressedRecordFlag = 0x00040000;

    struct ComplexFixture
    {
        std::vector<std::uint8_t> Bytes;
        std::size_t MinimalEnd = 0;
        std::size_t UncompressedRecordEnd = 0;
        std::size_t GroupStart = 0;
        std::size_t GroupSizeOffset = 0;
        std::size_t CompressedSizeOffset = 0;
        std::size_t CompressedPayloadOffset = 0;
    };

    void AppendUInt16(std::vector<std::uint8_t>& bytes, std::uint16_t value)
    {
        bytes.push_back(static_cast<std::uint8_t>(value));
        bytes.push_back(static_cast<std::uint8_t>(value >> 8));
    }

    void AppendUInt32(std::vector<std::uint8_t>& bytes, std::uint32_t value)
    {
        bytes.push_back(static_cast<std::uint8_t>(value));
        bytes.push_back(static_cast<std::uint8_t>(value >> 8));
        bytes.push_back(static_cast<std::uint8_t>(value >> 16));
        bytes.push_back(static_cast<std::uint8_t>(value >> 24));
    }

    void ReplaceUInt16(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint16_t value)
    {
        bytes.at(offset) = static_cast<std::uint8_t>(value);
        bytes.at(offset + 1) = static_cast<std::uint8_t>(value >> 8);
    }

    void ReplaceUInt32(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint32_t value)
    {
        bytes.at(offset) = static_cast<std::uint8_t>(value);
        bytes.at(offset + 1) = static_cast<std::uint8_t>(value >> 8);
        bytes.at(offset + 2) = static_cast<std::uint8_t>(value >> 16);
        bytes.at(offset + 3) = static_cast<std::uint8_t>(value >> 24);
    }

    void AppendSignature(std::vector<std::uint8_t>& bytes, const char signature[5])
    {
        bytes.insert(bytes.end(), signature, signature + 4);
    }

    std::vector<std::uint8_t> CreateSubRecord(const char signature[5], const std::vector<std::uint8_t>& data)
    {
        std::vector<std::uint8_t> bytes;
        AppendSignature(bytes, signature);
        AppendUInt16(bytes, static_cast<std::uint16_t>(data.size()));
        bytes.insert(bytes.end(), data.begin(), data.end());
        return bytes;
    }

    std::vector<std::uint8_t> CreateRecord(
        const char signature[5],
        std::uint32_t formId,
        std::uint32_t flags,
        const std::vector<std::uint8_t>& data)
    {
        std::vector<std::uint8_t> bytes;
        AppendSignature(bytes, signature);
        AppendUInt32(bytes, static_cast<std::uint32_t>(data.size()));
        AppendUInt32(bytes, flags);
        AppendUInt32(bytes, formId);
        AppendUInt32(bytes, 0);
        AppendUInt16(bytes, 44);
        AppendUInt16(bytes, 0);
        bytes.insert(bytes.end(), data.begin(), data.end());
        return bytes;
    }

    std::vector<std::uint8_t> CreateGroup(const std::vector<std::uint8_t>& content)
    {
        std::vector<std::uint8_t> bytes;
        AppendSignature(bytes, "GRUP");
        AppendUInt32(bytes, static_cast<std::uint32_t>(24 + content.size()));
        AppendSignature(bytes, "BOOK");
        AppendUInt32(bytes, 0);
        AppendUInt32(bytes, 0);
        AppendUInt32(bytes, 0);
        bytes.insert(bytes.end(), content.begin(), content.end());
        return bytes;
    }

    std::vector<std::uint8_t> CreateMinimalFixture()
    {
        return CreateRecord("TES4", 0, 0, CreateSubRecord("HEDR", { 0, 0, 0, 0 }));
    }

    ComplexFixture CreateComplexFixture()
    {
        ComplexFixture fixture;
        fixture.Bytes = CreateMinimalFixture();
        fixture.MinimalEnd = fixture.Bytes.size();

        const std::vector<std::uint8_t> full = CreateSubRecord(
            "FULL",
            { 'H', 'e', 'l', 'l', 'o', 0 });
        const std::vector<std::uint8_t> book = CreateRecord("BOOK", 0x01000001, 0, full);
        fixture.Bytes.insert(fixture.Bytes.end(), book.begin(), book.end());
        fixture.UncompressedRecordEnd = fixture.Bytes.size();

        const std::uint8_t compressedBytes[]{
            0x78, 0x9C, 0x73, 0x0B, 0xF5, 0xF1, 0x61, 0x63, 0xF0, 0x48, 0xCD,
            0xC9, 0xC9, 0x67, 0x00, 0x00, 0x14, 0x4A, 0x03, 0x2E
        };
        std::vector<std::uint8_t> compressedData;
        AppendUInt32(compressedData, static_cast<std::uint32_t>(full.size()));
        compressedData.insert(compressedData.end(), std::begin(compressedBytes), std::end(compressedBytes));
        const std::vector<std::uint8_t> compressedRecord =
            CreateRecord("BOOK", 0x01000002, CompressedRecordFlag, compressedData);

        fixture.GroupStart = fixture.Bytes.size();
        const std::vector<std::uint8_t> group = CreateGroup(compressedRecord);
        fixture.GroupSizeOffset = fixture.GroupStart + 4;
        fixture.CompressedSizeOffset = fixture.GroupStart + 24 + 24;
        fixture.CompressedPayloadOffset = fixture.CompressedSizeOffset + 4;
        fixture.Bytes.insert(fixture.Bytes.end(), group.begin(), group.end());
        return fixture;
    }

    std::vector<std::uint8_t> CreateNestedFixture(std::size_t groupCount)
    {
        std::vector<std::uint8_t> content = CreateRecord("BOOK", 0x01000003, 0, {});
        for (std::size_t index = 0; index < groupCount; ++index)
            content = CreateGroup(content);

        std::vector<std::uint8_t> bytes = CreateMinimalFixture();
        bytes.insert(bytes.end(), content.begin(), content.end());
        return bytes;
    }

    std::vector<std::uint8_t> CreateExtendedSubRecordFixture()
    {
        std::vector<std::uint8_t> data;
        AppendSignature(data, "XXXX");
        AppendUInt16(data, 4);
        AppendUInt32(data, 70000);
        AppendSignature(data, "FULL");
        AppendUInt16(data, 0);
        data.insert(data.end(), 69999, static_cast<std::uint8_t>('A'));
        data.push_back(0);

        std::vector<std::uint8_t> bytes = CreateMinimalFixture();
        const std::vector<std::uint8_t> record = CreateRecord("BOOK", 0x01000004, 0, data);
        bytes.insert(bytes.end(), record.begin(), record.end());
        return bytes;
    }

    class TemporaryFile
    {
    public:
        explicit TemporaryFile(const std::wstring& extension = L".esp")
        {
            static std::atomic<unsigned long> sequence{ 0 };
            _path = std::filesystem::temp_directory_path() /
                (L"EspReaderTests-" + std::to_wstring(++sequence) + extension);
        }

        ~TemporaryFile()
        {
            std::error_code error;
            std::filesystem::remove(_path, error);
        }

        const std::filesystem::path& Path() const noexcept
        {
            return _path;
        }

        void Write(const std::vector<std::uint8_t>& bytes) const
        {
            std::ofstream output(_path, std::ios::binary | std::ios::trunc);
            if (!output)
                throw std::runtime_error("Unable to create a temporary ESP fixture.");
            output.write(
                reinterpret_cast<const char*>(bytes.data()),
                static_cast<std::streamsize>(bytes.size()));
            if (!output)
                throw std::runtime_error("Unable to write a temporary ESP fixture.");
        }

        std::vector<std::uint8_t> Read() const
        {
            std::ifstream input(_path, std::ios::binary | std::ios::ate);
            if (!input)
                throw std::runtime_error("Unable to open a temporary ESP fixture.");
            const std::streamsize size = input.tellg();
            input.seekg(0, std::ios::beg);
            std::vector<std::uint8_t> bytes(static_cast<std::size_t>(size));
            input.read(reinterpret_cast<char*>(bytes.data()), size);
            if (!input)
                throw std::runtime_error("Unable to read a temporary ESP fixture.");
            return bytes;
        }

    private:
        std::filesystem::path _path;
    };

    std::filesystem::path GetTestModuleDirectory()
    {
        HMODULE module = nullptr;
        const BOOL found = GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCWSTR>(&GetTestModuleDirectory),
            &module);
        if (!found)
            throw std::runtime_error("Unable to locate the test module.");

        std::wstring path(MAX_PATH, L'\0');
        const DWORD length = GetModuleFileNameW(module, &path[0], static_cast<DWORD>(path.size()));
        if (length == 0 || length == path.size())
            throw std::runtime_error("Unable to resolve the test module path.");
        path.resize(length);
        return std::filesystem::path(path).parent_path();
    }

    int HexValue(char value)
    {
        if (value >= '0' && value <= '9')
            return value - '0';
        if (value >= 'A' && value <= 'F')
            return value - 'A' + 10;
        if (value >= 'a' && value <= 'f')
            return value - 'a' + 10;
        return -1;
    }

    std::vector<std::uint8_t> ReadHexFixture(const wchar_t* name)
    {
        const std::filesystem::path path = GetTestModuleDirectory() / L"Fixtures" / name;
        std::ifstream input(path, std::ios::binary);
        if (!input)
            throw std::runtime_error("Unable to open a documented parser fixture.");

        std::vector<std::uint8_t> bytes;
        int highNibble = -1;
        char character = 0;
        while (input.get(character))
        {
            if (std::isspace(static_cast<unsigned char>(character)))
                continue;

            const int value = HexValue(character);
            if (value < 0)
                throw std::runtime_error("A parser fixture contains a non-hexadecimal character.");

            if (highNibble < 0)
                highNibble = value;
            else
            {
                bytes.push_back(static_cast<std::uint8_t>((highNibble << 4) | value));
                highNibble = -1;
            }
        }

        if (highNibble >= 0 || bytes.empty())
            throw std::runtime_error("A parser fixture contains an incomplete hexadecimal byte.");
        return bytes;
    }

    bool ContainsSequence(
        const std::vector<std::uint8_t>& bytes,
        const std::vector<std::uint8_t>& sequence)
    {
        return !sequence.empty() &&
            std::search(bytes.begin(), bytes.end(), sequence.begin(), sequence.end()) != bytes.end();
    }

    class EspApi
    {
    public:
        using CreateInstance = void*(*)();
        using DestroyInstance = void(*)(void*);
        using SetFilter = int(*)(void*, const char*, const char**, int);
        using ReadEsp = int(*)(void*, const wchar_t*);
        using SaveEsp = bool(*)(void*, const char*);
        using SearchBySig = void**(*)(void*, const char*, const char*, int*);
        using FreeSearchResults = void(*)(void**, int);
        using GetSubRecordCount = int(*)(void*);
        using GetSubRecordData = const void*(*)(void*, int);
        using GetSubRecordString = const char*(*)(const void*);
        using IsSubRecordLocalized = bool(*)(const void*);
        using GetSubRecordStringId = std::uint32_t(*)(const void*);
        using ModifySubRecord = bool(*)(
            void*,
            std::uint32_t,
            const char*,
            const char*,
            int,
            int,
            const char*);

        EspApi()
        {
            const std::filesystem::path testDirectory = GetTestModuleDirectory();
            std::vector<std::filesystem::path> candidates{
                testDirectory / L"EspReader.dll",
                testDirectory.parent_path() / L"Release" / L"EspReader.dll",
                testDirectory.parent_path().parent_path().parent_path() / L"x64" / L"Release" / L"EspReader.dll"
            };
            for (const std::filesystem::path& candidate : candidates)
            {
                _library = LoadLibraryW(candidate.c_str());
                if (_library != nullptr)
                    break;
            }
            if (_library == nullptr)
                throw std::runtime_error("EspReader.dll could not be loaded.");

            Create = Get<CreateInstance>("C_CreateInstance");
            Destroy = Get<DestroyInstance>("C_DestroyInstance");
            ConfigureFilter = Get<SetFilter>("C_SetFilter");
            Read = Get<ReadEsp>("C_ReadEsp");
            Save = Get<SaveEsp>("C_SaveEsp");
            Search = Get<SearchBySig>("C_SearchBySig");
            FreeResults = Get<FreeSearchResults>("FreeSearchResults");
            GetSubCount = Get<GetSubRecordCount>("C_GetSubRecordCount");
            GetSubData = Get<GetSubRecordData>("C_GetSubRecordData_Ptr");
            GetSubString = Get<GetSubRecordString>("C_SubRecordData_GetString");
            IsLocalized = Get<IsSubRecordLocalized>("C_SubRecordData_IsLocalized");
            GetStringId = Get<GetSubRecordStringId>("C_SubRecordData_GetStringID");
            Modify = Get<ModifySubRecord>("C_ModifySubRecord");
        }

        ~EspApi()
        {
            FreeLibrary(_library);
        }

        EspApi(const EspApi&) = delete;
        EspApi& operator=(const EspApi&) = delete;

        CreateInstance Create = nullptr;
        DestroyInstance Destroy = nullptr;
        SetFilter ConfigureFilter = nullptr;
        ReadEsp Read = nullptr;
        SaveEsp Save = nullptr;
        SearchBySig Search = nullptr;
        FreeSearchResults FreeResults = nullptr;
        GetSubRecordCount GetSubCount = nullptr;
        GetSubRecordData GetSubData = nullptr;
        GetSubRecordString GetSubString = nullptr;
        IsSubRecordLocalized IsLocalized = nullptr;
        GetSubRecordStringId GetStringId = nullptr;
        ModifySubRecord Modify = nullptr;

    private:
        template<typename T>
        T Get(const char* name)
        {
            T function = reinterpret_cast<T>(GetProcAddress(_library, name));
            if (function == nullptr)
                throw std::runtime_error(std::string("Missing EspReader export: ") + name);
            return function;
        }

        HMODULE _library = nullptr;
    };

    class EspHandle
    {
    public:
        explicit EspHandle(EspApi& api) : _api(api), _handle(api.Create())
        {
            if (_handle == nullptr)
                throw std::runtime_error("Unable to create an EspReader instance.");
        }

        ~EspHandle()
        {
            _api.Destroy(_handle);
        }

        operator void*() const noexcept
        {
            return _handle;
        }

    private:
        EspApi& _api;
        void* _handle;
    };

    int ReadFixture(
        EspApi& api,
        void* handle,
        const std::vector<std::uint8_t>& bytes,
        const std::wstring& extension = L".esp")
    {
        TemporaryFile file(extension);
        file.Write(bytes);
        return api.Read(handle, file.Path().c_str());
    }
}

namespace EspReaderTests
{
    TEST_CLASS(EspReaderParserTests)
    {
    public:
        TEST_METHOD(LoadsDocumentedUtf8AndLocalizedFixtures)
        {
            EspApi api;
            EspHandle handle(api);
            const char* children[]{ "FULL" };
            Assert::AreEqual(1, api.ConfigureFilter(handle, "BOOK", children, 1));

            const std::vector<std::uint8_t> utf8Fixture =
                ReadHexFixture(L"valid-roundtrip.esp.hex");
            Assert::AreEqual(0, ReadFixture(api, handle, utf8Fixture));

            int count = 0;
            void** records = api.Search(handle, "BOOK", "FULL", &count);
            Assert::AreEqual(1, count);
            Assert::IsNotNull(records);
            const void* utf8Subrecord = api.GetSubData(records[0], 0);
            Assert::IsNotNull(utf8Subrecord);
            const std::string expectedUtf8 =
                "Gr\xC3\xBC\xC3\x9F" "e \xE6\x9D\xB1\xE4\xBA\xAC";
            Assert::AreEqual(
                expectedUtf8,
                std::string(api.GetSubString(utf8Subrecord)));
            Assert::IsFalse(api.IsLocalized(utf8Subrecord));
            api.FreeResults(records, count);

            const std::vector<std::uint8_t> localizedFixture =
                ReadHexFixture(L"localized.esm.hex");
            Assert::AreEqual(0, ReadFixture(api, handle, localizedFixture, L".esm"));

            count = 0;
            records = api.Search(handle, "BOOK", "FULL", &count);
            Assert::AreEqual(1, count);
            Assert::IsNotNull(records);
            const void* localizedSubrecord = api.GetSubData(records[0], 0);
            Assert::IsNotNull(localizedSubrecord);
            Assert::IsTrue(api.IsLocalized(localizedSubrecord));
            Assert::AreEqual<std::uint32_t>(0x12345678, api.GetStringId(localizedSubrecord));
            api.FreeResults(records, count);
        }

        TEST_METHOD(RejectsDocumentedMalformedFixture)
        {
            EspApi api;
            EspHandle handle(api);
            Assert::AreEqual(
                1,
                ReadFixture(
                    api,
                    handle,
                    ReadHexFixture(L"malformed-truncated.esp.hex")));
        }

        TEST_METHOD(ModifiesSavesAndParsesAgainWhilePreservingUnknownData)
        {
            EspApi api;
            EspHandle handle(api);
            TemporaryFile input;
            TemporaryFile output;
            const std::vector<std::uint8_t> fixture =
                ReadHexFixture(L"valid-roundtrip.esp.hex");
            input.Write(fixture);

            const char* children[]{ "FULL" };
            Assert::AreEqual(1, api.ConfigureFilter(handle, "BOOK", children, 1));
            Assert::AreEqual(0, api.Read(handle, input.Path().c_str()));
            const std::string replacement =
                "Neu: Gr\xC3\xBC\xC3\x9F" "e \xE6\x9D\xB1\xE4\xBA\xAC";
            Assert::IsTrue(api.Modify(
                handle,
                0x01000001,
                "BOOK",
                "FULL",
                0,
                0,
                replacement.c_str()));
            Assert::IsTrue(api.Save(handle, output.Path().u8string().c_str()));

            const std::vector<std::uint8_t> outputBytes = output.Read();
            const std::vector<std::uint8_t> unknownSubrecord{
                'U', 'N', 'K', 'N', 0x06, 0x00, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x7F
            };
            Assert::IsTrue(ContainsSequence(outputBytes, unknownSubrecord));

            EspHandle reparsedHandle(api);
            Assert::AreEqual(1, api.ConfigureFilter(reparsedHandle, "BOOK", children, 1));
            Assert::AreEqual(0, api.Read(reparsedHandle, output.Path().c_str()));

            int count = 0;
            void** records = api.Search(reparsedHandle, "BOOK", "FULL", &count);
            Assert::AreEqual(1, count);
            Assert::IsNotNull(records);
            const void* subrecord = api.GetSubData(records[0], 0);
            Assert::IsNotNull(subrecord);
            Assert::AreEqual(std::string(replacement), std::string(api.GetSubString(subrecord)));
            api.FreeResults(records, count);
        }

        TEST_METHOD(LoadsAndExtractsUncompressedAndCompressedRecords)
        {
            EspApi api;
            EspHandle handle(api);
            const char* children[]{ "FULL" };
            Assert::AreEqual(1, api.ConfigureFilter(handle, "BOOK", children, 1));

            const ComplexFixture fixture = CreateComplexFixture();
            Assert::AreEqual(0, ReadFixture(api, handle, fixture.Bytes));

            int count = 0;
            void** records = api.Search(handle, "BOOK", "FULL", &count);
            Assert::AreEqual(2, count);
            Assert::IsNotNull(records);
            for (int index = 0; index < count; ++index)
            {
                Assert::AreEqual(1, api.GetSubCount(records[index]));
                const void* subrecord = api.GetSubData(records[index], 0);
                Assert::IsNotNull(subrecord);
                Assert::AreEqual(std::string("Hello"), std::string(api.GetSubString(subrecord)));
            }
            api.FreeResults(records, count);
        }

        TEST_METHOD(RejectsEveryTruncatedMinimalRecordPrefix)
        {
            EspApi api;
            EspHandle handle(api);
            const std::vector<std::uint8_t> fixture = CreateMinimalFixture();
            for (std::size_t length = 0; length < fixture.size(); ++length)
            {
                const std::vector<std::uint8_t> prefix(fixture.begin(), fixture.begin() + length);
                Assert::AreEqual(1, ReadFixture(api, handle, prefix));
            }
        }

        TEST_METHOD(RejectsTruncationWithinRecordsAndGroups)
        {
            EspApi api;
            EspHandle handle(api);
            const ComplexFixture fixture = CreateComplexFixture();

            for (std::size_t length = fixture.MinimalEnd + 1; length < fixture.UncompressedRecordEnd; ++length)
            {
                const std::vector<std::uint8_t> prefix(fixture.Bytes.begin(), fixture.Bytes.begin() + length);
                Assert::AreEqual(1, ReadFixture(api, handle, prefix));
            }
            for (std::size_t length = fixture.GroupStart + 1; length < fixture.Bytes.size(); ++length)
            {
                const std::vector<std::uint8_t> prefix(fixture.Bytes.begin(), fixture.Bytes.begin() + length);
                Assert::AreEqual(1, ReadFixture(api, handle, prefix));
            }
        }

        TEST_METHOD(RejectsMalformedLengthsBeforeAllocation)
        {
            EspApi api;
            EspHandle handle(api);

            std::vector<std::uint8_t> invalidRecord = CreateMinimalFixture();
            ReplaceUInt32(invalidRecord, 4, 0xFFFFFFFF);
            Assert::AreEqual(1, ReadFixture(api, handle, invalidRecord));

            std::vector<std::uint8_t> invalidSubrecord = CreateMinimalFixture();
            ReplaceUInt16(invalidSubrecord, 28, 0xFFFF);
            Assert::AreEqual(1, ReadFixture(api, handle, invalidSubrecord));

            ComplexFixture invalidGroup = CreateComplexFixture();
            ReplaceUInt32(invalidGroup.Bytes, invalidGroup.GroupSizeOffset, 23);
            Assert::AreEqual(1, ReadFixture(api, handle, invalidGroup.Bytes));

            invalidGroup = CreateComplexFixture();
            ReplaceUInt32(invalidGroup.Bytes, invalidGroup.GroupSizeOffset, 0xFFFFFFFF);
            Assert::AreEqual(1, ReadFixture(api, handle, invalidGroup.Bytes));

            ComplexFixture invalidDecompressedSize = CreateComplexFixture();
            ReplaceUInt32(invalidDecompressedSize.Bytes, invalidDecompressedSize.CompressedSizeOffset, 536870913);
            Assert::AreEqual(1, ReadFixture(api, handle, invalidDecompressedSize.Bytes));

            ComplexFixture invalidCompressedData = CreateComplexFixture();
            invalidCompressedData.Bytes[invalidCompressedData.CompressedPayloadOffset] ^= 0xFF;
            Assert::AreEqual(1, ReadFixture(api, handle, invalidCompressedData.Bytes));
        }

        TEST_METHOD(RejectsExcessiveGroupNesting)
        {
            EspApi api;
            EspHandle handle(api);

            Assert::AreEqual(0, ReadFixture(api, handle, CreateNestedFixture(128)));
            Assert::AreEqual(1, ReadFixture(api, handle, CreateNestedFixture(129)));
        }

        TEST_METHOD(PreservesExtendedSubrecordsDuringRoundTrip)
        {
            EspApi api;
            EspHandle handle(api);
            TemporaryFile input;
            TemporaryFile output;
            const std::vector<std::uint8_t> fixture = CreateExtendedSubRecordFixture();
            input.Write(fixture);

            Assert::AreEqual(0, api.Read(handle, input.Path().c_str()));
            Assert::IsTrue(api.Save(handle, output.Path().u8string().c_str()));
            Assert::IsTrue(fixture == output.Read());
        }

        TEST_METHOD(FailedReadPreservesPreviousValidHandleState)
        {
            EspApi api;
            EspHandle handle(api);
            TemporaryFile valid;
            TemporaryFile invalid;
            TemporaryFile output;
            const ComplexFixture fixture = CreateComplexFixture();
            valid.Write(fixture.Bytes);
            std::vector<std::uint8_t> malformed = fixture.Bytes;
            ReplaceUInt32(malformed, fixture.GroupSizeOffset, 0xFFFFFFFF);
            invalid.Write(malformed);

            Assert::AreEqual(0, api.Read(handle, valid.Path().c_str()));
            Assert::AreEqual(1, api.Read(handle, invalid.Path().c_str()));
            Assert::IsTrue(api.Save(handle, output.Path().u8string().c_str()));
            Assert::IsTrue(fixture.Bytes == output.Read());
            Assert::AreEqual(-1, api.Read(nullptr, valid.Path().c_str()));
        }
    };
}
