#include "EspParser.h"

#include <cstdint>
#include <cstring>
#include <memory>
#include <unordered_map>
#include <vector>

#include "EspBinaryReader.h"
#include "EspCompression.h"
#include "EspFormat.h"

namespace
{
    constexpr std::uint64_t MaxRecordCount = 10'000'000;
    constexpr std::uint64_t MaxGroupCount = 1'000'000;

    struct ParseBudget
    {
        std::uint64_t RecordCount = 0;
        std::uint64_t GroupCount = 0;

        void AddRecord(EspBinaryReader& reader)
        {
            if (++RecordCount > MaxRecordCount)
                reader.Reject("Plugin record count exceeds the configured limit.");
        }

        void AddGroup(EspBinaryReader& reader, std::uint32_t depth)
        {
            if (depth > MaxGroupDepth)
                reader.Reject("Plugin group nesting exceeds the configured limit.");
            if (++GroupCount > MaxGroupCount)
                reader.Reject("Plugin group count exceeds the configured limit.");
        }
    };

    class ParseContext final
    {
    public:
        ParseContext(
            EspData& data,
            CharacterTracker& characters,
            ESP_HeuristicAnalysis& analysis,
            const RecordFilter& sourceFilter)
            : Data(data), Characters(characters), Analysis(analysis)
        {
            Filter.AllowAll = sourceFilter.AllowAll;
            Filter.LoadFromConfig(sourceFilter.CurrentConfig);
        }

        EspData& Data;
        CharacterTracker& Characters;
        ESP_HeuristicAnalysis& Analysis;
        RecordFilter Filter;
        std::unordered_map<std::uint32_t, std::vector<std::uint32_t>> DeferredInfoLinks;
        std::unordered_map<std::uint32_t, std::vector<std::uint32_t>> DeferredVoiceTypeLinks;
        std::unordered_map<std::uint32_t, std::vector<std::uint32_t>> DeferredFactionLinks;
        std::unordered_map<std::uint32_t, std::vector<std::uint32_t>> DeferredRaceLinks;
    };

    void ParseSubRecords(
        ParseContext& context,
        EspBinaryReader& reader,
        std::uint64_t end,
        EspRecord& record)
    {
        record.OnRecordBegin();
        while (reader.Position() < end)
        {
            reader.RequireWithin(end, sizeof(SubRecordHeader), "Subrecord header");
            char signature[4]{};
            reader.Read(signature, sizeof(signature), "Subrecord signature");
            std::uint32_t dataSize = reader.ReadValue<std::uint16_t>("Subrecord size");

            if (std::memcmp(signature, "XXXX", 4) == 0)
            {
                if (dataSize != sizeof(std::uint32_t))
                    reader.Reject("Extended subrecord size marker has an invalid payload length.");

                dataSize = reader.ReadValue<std::uint32_t>("Extended subrecord size");
                reader.RequireWithin(end, sizeof(SubRecordHeader), "Extended subrecord header");
                reader.Read(signature, sizeof(signature), "Extended subrecord signature");
                const std::uint16_t encodedSize =
                    reader.ReadValue<std::uint16_t>("Extended subrecord encoded size");
                if (encodedSize != 0)
                    reader.Reject("Extended subrecord must use a zero 16-bit size field.");
            }

            reader.RequireWithin(end, dataSize, "Subrecord data");
            const std::vector<std::uint8_t> data = reader.ReadBytes(
                dataSize,
                MaxSubRecordDataSize,
                "Subrecord data");
            record.AddSubRecord(
                &context.Characters,
                &context.Analysis,
                signature,
                data.data(),
                data.size(),
                context.Filter);
        }

        reader.RequireEnd(end, "Subrecord range");
        record.OnRecordFinished(
            &context.Characters,
            &context.DeferredInfoLinks,
            &context.DeferredVoiceTypeLinks,
            &context.DeferredFactionLinks,
            &context.DeferredRaceLinks);
    }

    void ParseEntries(
        ParseContext& context,
        EspBinaryReader& reader,
        std::uint64_t end,
        std::uint32_t currentDialFormId,
        std::uint32_t depth,
        ParseBudget& budget);

    void ParseRecord(
        ParseContext& context,
        EspBinaryReader& reader,
        const char signature[4],
        std::uint64_t containerEnd,
        std::uint32_t currentDialFormId,
        bool insideGroup,
        ParseBudget& budget)
    {
        reader.RequireWithin(containerEnd, sizeof(RecordHeader) - 4, "Record header");
        RecordHeader header{};
        std::memcpy(header.Sig, signature, sizeof(header.Sig));
        header.DataSize = reader.ReadValue<std::uint32_t>("Record data size");
        header.Flags = reader.ReadValue<std::uint32_t>("Record flags");
        header.FormID = reader.ReadValue<std::uint32_t>("Record form ID");
        header.VersionCtrl = reader.ReadValue<std::uint32_t>("Record version control");
        header.Version = reader.ReadValue<std::uint16_t>("Record version");
        header.Unknown = reader.ReadValue<std::uint16_t>("Record unknown field");
        if (header.DataSize > MaxRecordDataSize)
            reader.Reject("Record data exceeds the configured allocation limit.");

        const std::uint64_t recordEnd = reader.SubrangeEnd(header.DataSize, containerEnd, "Record data");
        budget.AddRecord(reader);
        EspRecord record(header.Sig, header.FormID, header.Flags);

        if (std::memcmp(header.Sig, "TES4", 4) == 0)
            context.Filter.FileIsLocalized = (header.Flags & Tes4FlagLocalized) != 0;

        if (IsCompressed(header))
        {
            reader.RequireWithin(recordEnd, sizeof(std::uint32_t), "Compressed record size");
            const std::uint32_t uncompressedSize =
                reader.ReadValue<std::uint32_t>("Compressed record uncompressed size");
            if (uncompressedSize > MaxDecompressedRecordSize)
                reader.Reject("Decompressed record exceeds the configured allocation limit.");

            const std::size_t compressedSize = static_cast<std::size_t>(recordEnd - reader.Position());
            const std::vector<std::uint8_t> compressed = reader.ReadBytes(
                compressedSize,
                MaxRecordDataSize,
                "Compressed record data");
            std::vector<std::uint8_t> decompressed;
            if (!ZlibDecompress(compressed.data(), compressed.size(), decompressed, uncompressedSize))
                reader.Reject("Compressed record data is invalid.");

            EspBinaryReader decompressedReader(decompressed.data(), decompressed.size());
            ParseSubRecords(context, decompressedReader, decompressedReader.Size(), record);
        }
        else
        {
            ParseSubRecords(context, reader, recordEnd, record);
        }

        reader.RequireEnd(recordEnd, "Record data");
        if (!insideGroup || record.CheckSub())
            context.Data.AddRecord(record, context.Filter, currentDialFormId);
    }

    void ParseGroup(
        ParseContext& context,
        EspBinaryReader& reader,
        std::uint64_t containerEnd,
        std::uint32_t currentDialFormId,
        std::uint32_t depth,
        ParseBudget& budget)
    {
        reader.RequireWithin(containerEnd, sizeof(GroupHeader) - 4, "Group header");
        const std::uint32_t groupSize = reader.ReadValue<std::uint32_t>("Group size");
        char label[4]{};
        reader.Read(label, sizeof(label), "Group label");
        const std::uint32_t groupType = reader.ReadValue<std::uint32_t>("Group type");
        static_cast<void>(reader.ReadValue<std::uint32_t>("Group stamp"));
        static_cast<void>(reader.ReadValue<std::uint32_t>("Group unknown field"));
        if (groupSize < sizeof(GroupHeader))
            reader.Reject("Group size is smaller than its header.");

        budget.AddGroup(reader, depth);
        context.Data.IncrementGrupCount();
        const std::uint64_t groupEnd = reader.SubrangeEnd(
            groupSize - sizeof(GroupHeader),
            containerEnd,
            "Group data");

        std::uint32_t nextDialFormId = currentDialFormId;
        if (groupType != 0)
            std::memcpy(&nextDialFormId, label, sizeof(nextDialFormId));

        ParseEntries(context, reader, groupEnd, nextDialFormId, depth, budget);
        reader.RequireEnd(groupEnd, "Group data");
    }

    void ParseEntries(
        ParseContext& context,
        EspBinaryReader& reader,
        std::uint64_t end,
        std::uint32_t currentDialFormId,
        std::uint32_t depth,
        ParseBudget& budget)
    {
        while (reader.Position() < end)
        {
            reader.RequireWithin(end, 4, "Record or group signature");
            char signature[4]{};
            reader.Read(signature, sizeof(signature), "Record or group signature");
            if (IsGroupSignature(signature))
                ParseGroup(context, reader, end, currentDialFormId, depth + 1, budget);
            else
                ParseRecord(context, reader, signature, end, currentDialFormId, depth != 0, budget);
        }

        reader.RequireEnd(end, "Plugin container");
    }

    void FlushDeferredLinks(ParseContext& context)
    {
        CharacterTracker& characters = context.Characters;
        for (const auto& entry : context.DeferredInfoLinks)
        {
            const auto character = characters.Characters.find(entry.first);
            if (character != characters.Characters.end())
                character->second.LinkedInfos.insert(
                    character->second.LinkedInfos.end(), entry.second.begin(), entry.second.end());
        }
        for (const auto& entry : context.DeferredVoiceTypeLinks)
        {
            const auto voiceType = characters.VoiceTypeToNPC.find(entry.first);
            if (voiceType == characters.VoiceTypeToNPC.end())
                continue;

            const auto character = characters.Characters.find(voiceType->second);
            if (character != characters.Characters.end())
                character->second.LinkedVoiceTypes.insert(
                    character->second.LinkedVoiceTypes.end(), entry.second.begin(), entry.second.end());
        }
        for (const auto& entry : context.DeferredFactionLinks)
        {
            const auto character = characters.Characters.find(entry.first);
            if (character != characters.Characters.end())
                character->second.LinkedFactions.insert(
                    character->second.LinkedFactions.end(), entry.second.begin(), entry.second.end());
        }
        for (const auto& entry : context.DeferredRaceLinks)
        {
            const auto character = characters.Characters.find(entry.first);
            if (character != characters.Characters.end())
                character->second.LinkedRaces.insert(
                    character->second.LinkedRaces.end(), entry.second.begin(), entry.second.end());
        }
    }

}

EspParsedDocument::EspParsedDocument()
    : _data(std::make_unique<EspData>()),
      _characters(std::make_unique<CharacterTracker>()),
      _analysis(std::make_unique<ESP_HeuristicAnalysis>())
{
}

const EspData& EspParsedDocument::Data() const noexcept
{
    return *_data;
}

const CharacterTracker& EspParsedDocument::Characters() const noexcept
{
    return *_characters;
}

const ESP_HeuristicAnalysis& EspParsedDocument::Analysis() const noexcept
{
    return *_analysis;
}

bool EspParsedDocument::IsLocalized() const noexcept
{
    return _isLocalized;
}

std::unique_ptr<EspData> EspParsedDocument::TakeData() noexcept
{
    return std::move(_data);
}

std::unique_ptr<CharacterTracker> EspParsedDocument::TakeCharacters() noexcept
{
    return std::move(_characters);
}

std::unique_ptr<ESP_HeuristicAnalysis> EspParsedDocument::TakeAnalysis() noexcept
{
    return std::move(_analysis);
}

EspParsedDocument EspParser::Parse(std::ifstream& stream, const RecordFilter& filter)
{
    EspBinaryReader reader(stream);
    return Parse(reader, filter);
}

EspParsedDocument EspParser::Parse(
    const std::uint8_t* data,
    std::size_t size,
    const RecordFilter& filter)
{
    EspBinaryReader reader(data, size);
    return Parse(reader, filter);
}

EspParsedDocument EspParser::Parse(EspBinaryReader& reader, const RecordFilter& filter)
{
    EspParsedDocument document;
    ParseContext context(*document._data, *document._characters, *document._analysis, filter);
    ParseBudget budget;
    ParseEntries(context, reader, reader.Size(), 0, 0, budget);
    if (!document._data->HasTES4Header)
        reader.Reject("Plugin does not contain a TES4 header record.");

    FlushDeferredLinks(context);
    document._data->BuildDialTopologyIndex();
    document._isLocalized = context.Filter.FileIsLocalized;
    return document;
}
