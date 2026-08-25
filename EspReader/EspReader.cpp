#include <fstream>
#include <vector>
#include <string>
#include <iostream>
#include <cstdint>
#include <stack>
#include <unordered_map>
#include <unordered_set>
#include <random>
#include <mutex>
#include <limits>
#include <memory>
#include <stdexcept>

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "EspReaderApi.h"
#include "EspBinaryReader.h"
#include "EspCompression.h"
#include "EspFormat.h"
#include "EspParser.h"

class EspInstance
{
    public:
    std::unique_ptr<ESP_HeuristicAnalysis> TextValidator;
    std::unique_ptr<CharacterTracker> CharTracker;
    std::unique_ptr<EspData> Data;
    std::unique_ptr<RecordFilter> Filter;
    std::wstring            LastSetPath;

    // Character index cache
    std::vector<const CharacterRecord*> CharacterIndexCache;
    bool                    CharacterCacheDirty = true;

    EspInstance()
        : TextValidator(std::make_unique<ESP_HeuristicAnalysis>()),
          CharTracker(std::make_unique<CharacterTracker>()),
          Filter(std::make_unique<RecordFilter>())
    {
    }

    // Reset data only (keep filter/validator alive)
    void ClearData()
    {
        Data.reset();

        CharacterIndexCache.clear();
        CharacterCacheDirty = true;
        LastSetPath.clear();
    }
};

// ============================================================
//  Version string
// ============================================================
static const std::string Version = "1.0.0.7";

// ============================================================
//  Character cache helpers
// ============================================================
static void EnsureCharacterCache(EspInstance* inst)
{
    if (!inst) return;
    if (!inst->CharacterCacheDirty) return;
    inst->CharacterIndexCache.clear();
    if (!inst->CharTracker) return;
    for (const auto& kv : inst->CharTracker->Characters)
        inst->CharacterIndexCache.push_back(&kv.second);
    inst->CharacterCacheDirty = false;
}

static const CharacterRecord* GetCharacterAt(EspInstance* inst, int index)
{
    if (!inst) return nullptr;
    EnsureCharacterCache(inst);
    if (index < 0 || index >= static_cast<int>(inst->CharacterIndexCache.size())) return nullptr;
    return inst->CharacterIndexCache[index];
}

static int WriteStringToBuffer(const std::string& Str, uint8_t* Buffer, int BufferSize)
{
    int Len = static_cast<int>(Str.size());
    if (Buffer && BufferSize > Len) { std::memcpy(Buffer, Str.c_str(), Len); Buffer[Len] = 0; }
    return Len;
}

// ============================================================
//  Save helpers (unchanged logic, use inst->Data and inst->LastSetPath)
// ============================================================
static inline uint64_t MakeRecordKey(uint32_t FormID, const char Sig[4])
{
    uint32_t SigInt = 0; std::memcpy(&SigInt, Sig, 4);
    return (static_cast<uint64_t>(FormID) << 32) | static_cast<uint64_t>(SigInt);
}
static inline uint64_t MakeRecordKey(uint32_t FormID, const std::string& Sig)
{
    return MakeRecordKey(FormID, Sig.c_str());
}

struct OriginalSubRecord
{
    std::string Sig;
    int OccurrenceIndex = 0;
    std::size_t SerializedOffset = 0;
    std::size_t SerializedSize = 0;
};

static std::unordered_map<uint64_t, const EspRecord*> BuildModifiedIndex(EspInstance* inst)
{
    std::unordered_map<uint64_t, const EspRecord*> index;
    auto scan = [&](const std::vector<EspRecord>& records) {
        for (const auto& rec : records)
            for (const auto& sub : rec.SubRecords)
                if (sub.IsModify) { index[MakeRecordKey(rec.FormID, rec.Sig)] = &rec; break; }
        };
    scan(inst->Data->Records);
    scan(inst->Data->CellRecords);
    return index;
}

static std::vector<OriginalSubRecord> ParseOriginalSubRecords(const uint8_t* data, size_t dataSize)
{
    std::vector<OriginalSubRecord> result;
    std::unordered_map<std::string, int> occ;
    EspBinaryReader reader(data, dataSize);
    while (reader.Remaining() != 0)
    {
        const std::size_t serializedOffset = static_cast<std::size_t>(reader.Position());
        reader.RequireWithin(reader.Size(), sizeof(SubRecordHeader), "Original subrecord header");
        char signature[4]{};
        reader.Read(signature, sizeof(signature), "Original subrecord signature");
        std::uint32_t size = reader.ReadValue<std::uint16_t>("Original subrecord size");
        if (std::memcmp(signature, "XXXX", 4) == 0)
        {
            if (size != sizeof(std::uint32_t))
                reader.Reject("Original extended subrecord marker has an invalid size.");

            size = reader.ReadValue<std::uint32_t>("Original extended subrecord size");
            reader.RequireWithin(reader.Size(), sizeof(SubRecordHeader), "Original extended subrecord header");
            reader.Read(signature, sizeof(signature), "Original extended subrecord signature");
            if (reader.ReadValue<std::uint16_t>("Original extended encoded size") != 0)
                reader.Reject("Original extended subrecord has a non-zero encoded size.");
        }

        if (size > MaxSubRecordDataSize)
            reader.Reject("Original subrecord exceeds the configured allocation limit.");
        reader.RequireWithin(reader.Size(), size, "Original subrecord data");
        reader.Skip(size, "Original subrecord data");

        OriginalSubRecord osr;
        osr.Sig = std::string(signature, 4);
        osr.OccurrenceIndex = occ[osr.Sig]++;
        osr.SerializedOffset = serializedOffset;
        osr.SerializedSize = static_cast<std::size_t>(reader.Position()) - serializedOffset;
        result.push_back(osr);
    }
    return result;
}

static const SubRecordData* FindModifiedSubRecord(
    const std::unordered_map<uint64_t, const EspRecord*>& index,
    const std::string& ParentSig, uint32_t FormID,
    const std::string& ChildSig, int OccurrenceIndex)
{
    auto it = index.find(MakeRecordKey(FormID, ParentSig));
    if (it == index.end()) return nullptr;
    for (const auto& sub : it->second->SubRecords)
        if (sub.Sig == ChildSig && sub.OccurrenceIndex == OccurrenceIndex && sub.IsModify) return &sub;
    return nullptr;
}

static std::vector<uint8_t> ModifySubRecordsWithFilter(
    const uint8_t* originalData, size_t dataSize,
    const std::string& parentSig, uint32_t formID,
    const std::unordered_map<uint64_t, const EspRecord*>& modifiedIndex)
{
    std::vector<uint8_t> result;
    auto originalSubs = ParseOriginalSubRecords(originalData, dataSize);
    for (const auto& osr : originalSubs)
    {
        const SubRecordData* modified = FindModifiedSubRecord(
            modifiedIndex,
            parentSig,
            formID,
            osr.Sig,
            osr.OccurrenceIndex);
        if (modified)
        {
            if (modified->Data.size() > MaxSubRecordDataSize)
                throw std::length_error("Modified subrecord exceeds the configured allocation limit.");

            if (modified->Data.size() > (std::numeric_limits<std::uint16_t>::max)())
            {
                SubRecordHeader extendedHeader{};
                std::memcpy(extendedHeader.Sig, "XXXX", sizeof(extendedHeader.Sig));
                extendedHeader.Size = sizeof(std::uint32_t);
                result.insert(
                    result.end(),
                    reinterpret_cast<const std::uint8_t*>(&extendedHeader),
                    reinterpret_cast<const std::uint8_t*>(&extendedHeader) + sizeof(extendedHeader));
                const std::uint32_t extendedSize = static_cast<std::uint32_t>(modified->Data.size());
                result.insert(
                    result.end(),
                    reinterpret_cast<const std::uint8_t*>(&extendedSize),
                    reinterpret_cast<const std::uint8_t*>(&extendedSize) + sizeof(extendedSize));
            }

            SubRecordHeader newHeader{};
            std::memcpy(newHeader.Sig, osr.Sig.c_str(), sizeof(newHeader.Sig));
            newHeader.Size = modified->Data.size() > (std::numeric_limits<std::uint16_t>::max)()
                ? 0
                : static_cast<std::uint16_t>(modified->Data.size());
            result.insert(
                result.end(),
                reinterpret_cast<const std::uint8_t*>(&newHeader),
                reinterpret_cast<const std::uint8_t*>(&newHeader) + sizeof(newHeader));
            result.insert(result.end(), modified->Data.begin(), modified->Data.end());
        }
        else
        {
            result.insert(
                result.end(),
                originalData + osr.SerializedOffset,
                originalData + osr.SerializedOffset + osr.SerializedSize);
        }

        if (result.size() > MaxDecompressedRecordSize)
            throw std::length_error("Modified record exceeds the configured allocation limit.");
    }
    return result;
}

static void WriteOutput(std::ofstream& output, const void* data, std::size_t size, const char* context)
{
    if (size > static_cast<std::size_t>((std::numeric_limits<std::streamsize>::max)()))
        throw std::length_error(std::string(context) + " exceeds the stream write limit.");
    if (size == 0)
        return;

    output.write(static_cast<const char*>(data), static_cast<std::streamsize>(size));
    if (!output)
        throw std::runtime_error(std::string(context) + " could not be written completely.");
}

static void ProcessGroup(
    EspBinaryReader& reader,
    std::ofstream& output,
    std::uint64_t containerEnd,
    const std::unordered_map<uint64_t, const EspRecord*>& index,
    std::uint32_t depth);

static void ProcessContent(
    EspBinaryReader& reader,
    std::ofstream& output,
    std::uint64_t end,
    const std::unordered_map<uint64_t, const EspRecord*>& index,
    std::uint32_t depth);

static void ProcessRecord(EspBinaryReader& reader, std::ofstream& output, const char Sig[4],
    std::uint64_t containerEnd,
    const std::unordered_map<uint64_t, const EspRecord*>& modifiedIndex)
{
    reader.RequireWithin(containerEnd, sizeof(RecordHeader) - 4, "Saved record header");
    RecordHeader HDR{};
    std::memcpy(HDR.Sig, Sig, sizeof(HDR.Sig));
    HDR.DataSize = reader.ReadValue<std::uint32_t>("Saved record data size");
    HDR.Flags = reader.ReadValue<std::uint32_t>("Saved record flags");
    HDR.FormID = reader.ReadValue<std::uint32_t>("Saved record form ID");
    HDR.VersionCtrl = reader.ReadValue<std::uint32_t>("Saved record version control");
    HDR.Version = reader.ReadValue<std::uint16_t>("Saved record version");
    HDR.Unknown = reader.ReadValue<std::uint16_t>("Saved record unknown field");
    if (HDR.DataSize > MaxRecordDataSize)
        reader.Reject("Saved record exceeds the configured allocation limit.");
    const std::uint64_t recordEnd = reader.SubrangeEnd(HDR.DataSize, containerEnd, "Saved record data");
    std::vector<uint8_t> OriginalData = reader.ReadBytes(
        HDR.DataSize,
        MaxRecordDataSize,
        "Saved record data");

    if (modifiedIndex.find(MakeRecordKey(HDR.FormID, Sig)) == modifiedIndex.end())
    {
        WriteOutput(output, &HDR, sizeof(HDR), "Saved record header");
        WriteOutput(output, OriginalData.data(), OriginalData.size(), "Saved record data");
        reader.RequireEnd(recordEnd, "Saved record data");
        return;
    }

    std::vector<uint8_t> WorkingData;
    bool WasCompressed = IsCompressed(HDR);
    if (WasCompressed)
    {
        if (HDR.DataSize < 4)
            reader.Reject("Saved compressed record has no uncompressed-size field.");
        uint32_t UncompressedSize = 0;
        std::memcpy(&UncompressedSize, OriginalData.data(), sizeof(UncompressedSize));
        if (UncompressedSize > MaxDecompressedRecordSize ||
            !ZlibDecompress(
                OriginalData.data() + sizeof(UncompressedSize),
                OriginalData.size() - sizeof(UncompressedSize),
                WorkingData,
                UncompressedSize))
        {
            reader.Reject("Saved compressed record data is invalid.");
        }
    }
    else WorkingData = OriginalData;

    WorkingData = ModifySubRecordsWithFilter(
        WorkingData.data(),
        WorkingData.size(),
        std::string(Sig, 4),
        HDR.FormID,
        modifiedIndex);

    std::vector<uint8_t> FinalData;
    if (WasCompressed)
    {
        std::vector<uint8_t> Compressed;
        if (!ZlibCompress(WorkingData.data(), WorkingData.size(), Compressed))
            throw std::runtime_error("Modified record compression failed.");
        if (Compressed.size() > MaxRecordDataSize - sizeof(std::uint32_t))
            throw std::length_error("Modified compressed record exceeds the configured limit.");
        FinalData.resize(4 + Compressed.size());
        const uint32_t UncompSize = static_cast<uint32_t>(WorkingData.size());
        std::memcpy(FinalData.data(), &UncompSize, 4);
        std::memcpy(FinalData.data() + 4, Compressed.data(), Compressed.size());
    }
    else FinalData = WorkingData;

    if (FinalData.size() > MaxRecordDataSize ||
        FinalData.size() > (std::numeric_limits<std::uint32_t>::max)())
    {
        throw std::length_error("Modified record exceeds the ESP record-size limit.");
    }
    HDR.DataSize = static_cast<uint32_t>(FinalData.size());
    WriteOutput(output, &HDR, sizeof(HDR), "Modified record header");
    WriteOutput(output, FinalData.data(), FinalData.size(), "Modified record data");
    reader.RequireEnd(recordEnd, "Saved record data");
}

static void ProcessGroup(
    EspBinaryReader& reader,
    std::ofstream& output,
    std::uint64_t containerEnd,
    const std::unordered_map<uint64_t, const EspRecord*>& index,
    std::uint32_t depth)
{
    if (depth > MaxGroupDepth)
        reader.Reject("Saved group nesting exceeds the configured limit.");
    reader.RequireWithin(containerEnd, sizeof(GroupHeader) - 4, "Saved group header");
    GroupHeader header{};
    std::memcpy(header.Sig, "GRUP", sizeof(header.Sig));
    header.Size = reader.ReadValue<std::uint32_t>("Saved group size");
    reader.Read(header.Label, sizeof(header.Label), "Saved group label");
    header.GroupType = reader.ReadValue<std::uint32_t>("Saved group type");
    header.Stamp = reader.ReadValue<std::uint32_t>("Saved group stamp");
    header.Unknown = reader.ReadValue<std::uint32_t>("Saved group unknown field");
    if (header.Size < sizeof(GroupHeader))
        reader.Reject("Saved group size is smaller than its header.");
    const std::uint64_t groupEnd = reader.SubrangeEnd(
        header.Size - sizeof(GroupHeader),
        containerEnd,
        "Saved group data");

    const std::streampos headerPosition = output.tellp();
    if (headerPosition < 0)
        throw std::runtime_error("Unable to determine the saved group header position.");
    WriteOutput(output, &header, sizeof(header), "Saved group header");
    const std::streampos contentStart = output.tellp();
    if (contentStart < 0)
        throw std::runtime_error("Unable to determine the saved group content position.");

    ProcessContent(reader, output, groupEnd, index, depth);
    reader.RequireEnd(groupEnd, "Saved group data");
    const std::streampos contentEnd = output.tellp();
    if (contentEnd < contentStart)
        throw std::runtime_error("Saved group output position is invalid.");
    const std::uint64_t contentSize = static_cast<std::uint64_t>(contentEnd - contentStart);
    if (contentSize > (std::numeric_limits<std::uint32_t>::max)() - sizeof(GroupHeader))
        throw std::length_error("Saved group exceeds the ESP group-size limit.");
    const uint32_t actualGroupSize = static_cast<uint32_t>(contentSize + sizeof(GroupHeader));
    if (actualGroupSize != header.Size)
    {
        const std::streampos saved = output.tellp();
        output.seekp(headerPosition + std::streamoff(4));
        WriteOutput(output, &actualGroupSize, sizeof(actualGroupSize), "Updated group size");
        output.seekp(saved);
        if (!output)
            throw std::runtime_error("Unable to restore the saved group output position.");
    }
}

static void ProcessContent(
    EspBinaryReader& reader,
    std::ofstream& output,
    std::uint64_t end,
    const std::unordered_map<uint64_t, const EspRecord*>& index,
    std::uint32_t depth)
{
    while (reader.Position() < end)
    {
        reader.RequireWithin(end, 4, "Saved record or group signature");
        char signature[4]{};
        reader.Read(signature, sizeof(signature), "Saved record or group signature");
        if (IsGroupSignature(signature))
            ProcessGroup(reader, output, end, index, depth + 1);
        else
            ProcessRecord(reader, output, signature, end, index);
    }
    reader.RequireEnd(end, "Saved plugin container");
}

static std::mutex SaveEspLock;

static int SaveEsp_Inst(EspInstance* inst, const char* Utf8Path)
{
    std::lock_guard<std::mutex> Lock(SaveEspLock);

    if (!inst || inst->LastSetPath.empty() || !Utf8Path) return false;

    int Wlen = MultiByteToWideChar(CP_UTF8, 0, Utf8Path, -1, NULL, 0);
    if (Wlen == 0) return false;
    std::wstring WSavePath(Wlen, 0);
    if (MultiByteToWideChar(CP_UTF8, 0, Utf8Path, -1, &WSavePath[0], Wlen) == 0)
        return false;
    WSavePath.resize(static_cast<std::size_t>(Wlen - 1));

    if (WSavePath == inst->LastSetPath) return false;

    std::ifstream Fin(inst->LastSetPath, std::ios::binary);
    if (!Fin.is_open()) return false;

    std::ofstream Fout(WSavePath, std::ios::binary);
    if (!Fout.is_open()) { Fin.close(); return false; }

    static char ReadBuf[4 * 1024 * 1024];
    static char WriteBuf[4 * 1024 * 1024];
    Fin.rdbuf()->pubsetbuf(ReadBuf, sizeof(ReadBuf));
    Fout.rdbuf()->pubsetbuf(WriteBuf, sizeof(WriteBuf));

    try
    {
        EspBinaryReader reader(Fin);
        auto ModifiedIndex = BuildModifiedIndex(inst);
        ProcessContent(reader, Fout, reader.Size(), ModifiedIndex, 0);
        Fout.flush();
        bool Result = static_cast<bool>(Fout);
        if (Result)
        {
            return RESULT_OK;
        }
        else
        {
            return RESULT_ERROR;
        }
    }
    catch (...)
    {
        return RESULT_ERROR;
    }
}

// ABI adapters below are the only functions exported by the module.

static EspInstance* CreateInstanceImpl()
{
    return new EspInstance();
}
static void DestroyInstanceImpl(EspInstance* h) { delete h; }

static const char* GetVersionImpl() { return Version.c_str(); }
static int GetVersionLengthImpl() { return static_cast<int>(Version.length()); }

static void InitFilterImpl(EspInstance* h)
{
    if (!h) return;
    h->Filter = std::make_unique<RecordFilter>();
}

static int GetFilterImpl(EspInstance* h, uint8_t* buffer, int bufferSize)
{
    if (!h || !h->Filter) return RESULT_ERROR;
    std::string result;
    for (const auto& kv : h->Filter->CurrentConfig)
    {
        result += kv.first + ":";
        for (size_t i = 0; i < kv.second.size(); i++)
        {
            if (i > 0) result += ",";
            result += kv.second[i];
        }
        result += ";";
    }
    int len = static_cast<int>(result.size());
    if (buffer && bufferSize > len)
    {
        std::memcpy(buffer, result.c_str(), len);
        buffer[len] = 0;
    }
    return len;
}

static int SetSkyrimFilterImpl(EspInstance* h)
{
    if (!h || !h->Filter) return RESULT_ERROR;
    std::unordered_map<std::string, std::vector<std::string>> Config =
    {
       {"ACTI",{"FULL","RNAM"}},{"ALCH",{"FULL"}},{"AMMO",{"FULL","DESC"}},
       {"APPA",{"FULL","DESC"}},{"ARMO",{"FULL","DESC"}},{"AVIF",{"FULL","DESC"}},
       {"BOOK",{"FULL","DESC","CNAM"}},{"CLAS",{"FULL"}},{"CELL",{"FULL"}},
       {"CONT",{"FULL"}},{"DIAL",{"FULL"}},{"DOOR",{"FULL"}},{"ENCH",{"FULL"}},
       {"EXPL",{"FULL"}},{"FLOR",{"FULL","RNAM"}},{"FURN",{"FULL"}},{"HAZD",{"FULL"}},
       {"INFO",{"NAM1","RNAM"}},{"INGR",{"FULL"}},{"KEYM",{"FULL"}},{"LCTN",{"FULL"}},
       {"LIGH",{"FULL"}},{"LSCR",{"DESC"}},{"MESG",{"DESC","FULL","ITXT"}},
       {"MGEF",{"FULL","DNAM"}},{"MISC",{"FULL"}},{"NPC_",{"FULL","SHRT"}},
       {"NOTE",{"FULL","TNAM"}},{"PERK",{"FULL","DESC","EPF2","EPFD"}},{"PROJ",{"FULL"}},
       {"QUST",{"FULL","CNAM","NNAM"}},{"RACE",{"FULL","DESC"}},{"REFR",{"FULL"}},
       {"REGN",{"RDMP"}},{"SCRL",{"FULL","DESC"}},{"SHOU",{"FULL","DESC"}},
       {"SLGM",{"FULL"}},{"SPEL",{"FULL","DESC"}},{"TACT",{"FULL"}},{"TREE",{"FULL"}},
       {"WEAP",{"DESC","FULL"}},{"WOOP",{"FULL","TNAM"}},{"WRLD",{"FULL"}},
    };
    h->Filter->LoadFromConfig(Config);
    return static_cast<int>(h->Filter->CurrentConfig.size());
}

static int SetFilterImpl(EspInstance* h, const char* ParentSig, const char** ChildSigs, int ChildCount)
{
    if (!h || !h->Filter || !ParentSig) return RESULT_ERROR;
    std::string Parent(ParentSig);
    std::vector<std::string>& Vec = h->Filter->CurrentConfig[Parent];
    for (int i = 0; i < ChildCount; ++i) Vec.push_back(std::string(ChildSigs[i]));

    h->Filter->RebuildFilters();

    return static_cast<int>(Vec.size());
}

static void ClearFilterImpl(EspInstance* Handle)
{
    if (Handle && Handle->Filter)
    {
        Handle->Filter->ClearFilters();
    }
}


static C_LinkDIAL GetDialContextByDialImpl(EspInstance* handle, int RecordOffset)
{
    C_LinkDIAL result = {};
    if (!handle || !handle->Data) return result;

    std::unique_ptr<LinkDIAL> context(handle->Data->GetDialContextByDialIndex(RecordOffset));
    if (!context) return result;

    result.HasData = 1;
    result.Head.ResponseID = context->Head.ResponseID;
    result.Head.EmotionType = context->Head.EmotionType;
    result.Head.RecordOffset = context->Head.RecordOffset;
    result.Head.SubOffset = context->Head.SubOffset;

    result.LinkCount = (uint32_t)context->Links.size();
    if (result.LinkCount > 0)
    {
        auto linkArray = std::make_unique<C_DialResponseNode[]>(result.LinkCount);
        for (uint32_t i = 0; i < result.LinkCount; ++i)
        {
            linkArray[i].ResponseID = context->Links[i].ResponseID;
            linkArray[i].EmotionType = context->Links[i].EmotionType;
            linkArray[i].RecordOffset = context->Links[i].RecordOffset;
            linkArray[i].SubOffset = context->Links[i].SubOffset;
        }
        result.Links = linkArray.release();
    }

    return result;
}

// --- New dialogue context API ---

static C_LinkDIAL GetDialContextImpl(EspInstance* handle, int RecordOffset, int SubOffset)
{
    C_LinkDIAL result = {};
    if (!handle || !handle->Data) return result;

    std::unique_ptr<LinkDIAL> context(handle->Data->GetDialContextByIndex(RecordOffset, SubOffset));
    if (!context) return result;

    result.HasData = 1;
    // Head
    result.Head.ResponseID = context->Head.ResponseID;
    result.Head.EmotionType = context->Head.EmotionType;
    result.Head.RecordOffset = context->Head.RecordOffset;
    result.Head.SubOffset = context->Head.SubOffset;

    // Links
    result.LinkCount = static_cast<uint32_t>(context->Links.size());
    if (result.LinkCount > 0)
    {
        auto linkArray = std::make_unique<C_DialResponseNode[]>(result.LinkCount);
        for (size_t i = 0; i < result.LinkCount; ++i)
        {
            linkArray[i].ResponseID = context->Links[i].ResponseID;
            linkArray[i].EmotionType = context->Links[i].EmotionType;
            linkArray[i].RecordOffset = context->Links[i].RecordOffset;
            linkArray[i].SubOffset = context->Links[i].SubOffset;
        }
        result.Links = linkArray.release();
    }

    return result;
}

static void FreeDialContextImpl(C_LinkDIAL* context)
{
    if (!context) return;

    delete[] context->Links;
    context->Links = nullptr;
    context->LinkCount = 0;
    context->HasData = 0;
}

static int GetTitleIndexByBookDescImpl(EspInstance* Handle, int RecordOffset, int DescSubOffset)
{
    if (!Handle || !Handle->Data) return RESULT_ERROR;
    return Handle->Data->GetTitleIndexByBookDesc(RecordOffset, DescSubOffset);
}

static int GetDescIndexByBookTitleImpl(EspInstance* Handle, int RecordOffset, int DescSubOffset)
{
    if (!Handle || !Handle->Data) return RESULT_ERROR;
    return Handle->Data->GetDescIndexByBookTitle(RecordOffset, DescSubOffset);
}

// --- Other C API functions (unchanged) ---
//Returns 0 if the file is not found. Returns -1 if not initialized. Returns -2 on code error. A value greater than 0 indicates success.
static int ReadEspImpl(EspInstance* Instance, const wchar_t* EspPath)
{
    if (!Instance || !Instance->Filter || !EspPath) return RESULT_NOT_INITIALIZED;

    try
    {
        std::ifstream stream(EspPath, std::ios::binary);
        if (!stream.is_open()) return RESULT_NOT_FOUND;

        EspParsedDocument parsed = EspParser::Parse(stream, *Instance->Filter);
        Instance->Filter->FileIsLocalized = parsed.IsLocalized();
        Instance->TextValidator = parsed.TakeAnalysis();
        Instance->CharTracker = parsed.TakeCharacters();
        Instance->Data = parsed.TakeData();
        Instance->CharacterIndexCache.clear();
        Instance->CharacterCacheDirty = true;
        Instance->LastSetPath = EspPath;

        return RESULT_OK;
    }
    catch (...)
    {
        return RESULT_ERROR;
    }
}

static int SaveEspImpl(EspInstance* h, const char* Utf8Path)
{
    return SaveEsp_Inst(h, Utf8Path);
}

static void ClearImpl(EspInstance* h) { if (h) h->ClearData(); }

static const char* GetFieldReportImpl(EspInstance* h)
{
    if (!h || !h->TextValidator) { static const char* e = "Validator not initialized"; return e; }
    thread_local std::string buffer;
    buffer = h->TextValidator->ExportFieldReport();
    return buffer.c_str();
}
static int GetFieldReportLengthImpl(EspInstance* h)
{
    if (!h || !h->TextValidator) return 0;
    thread_local std::string buffer;
    buffer = h->TextValidator->ExportFieldReport();
    return static_cast<int>(buffer.length());
}

static EspRecord** SearchBySigImpl(EspInstance* h, const char* ParentSig, const char* ChildSig, int* OutCount)
{
    *OutCount = 0;
    if (!h || !h->Data) return nullptr;
    std::vector<EspRecord> Matches = h->Data->SearchBySig(ParentSig, ChildSig ? ChildSig : "");
    *OutCount = static_cast<int>(Matches.size());
    if (Matches.empty()) return nullptr;
    auto result = std::make_unique<EspRecord*[]>(static_cast<std::size_t>(*OutCount));
    std::vector<std::unique_ptr<EspRecord>> records;
    records.reserve(static_cast<std::size_t>(*OutCount));
    for (int i = 0; i < *OutCount; ++i)
    {
        records.push_back(std::make_unique<EspRecord>(Matches[static_cast<std::size_t>(i)]));
        result[static_cast<std::size_t>(i)] = records.back().get();
    }
    for (auto& record : records)
        record.release();
    return result.release();
}

static void FreeSearchResultsImpl(EspRecord** Arr, int Count)
{
    if (!Arr) return;
    for (int i = 0; i < Count; ++i) delete Arr[i];
    delete[] Arr;
}

// Record accessors (unchanged)
static const SubRecordData* GetSubRecordDataPtrImpl(EspRecord* r, int i)
{
    if (!r || i < 0 || i >= (int)r->SubRecords.size()) return nullptr; return &r->SubRecords[i];
}
static int GetRecordSigImpl(EspRecord* r, uint8_t* b, int bs)
{
    if (!r) return -1; int l = (int)r->Sig.size();
    if (b && bs > l) { std::memcpy(b, r->Sig.c_str(), l); b[l] = 0; } return l;
}
static uint32_t GetRecordFormIdImpl(EspRecord* r) { return r ? r->FormID : 0; }
static const char* GetRecordEditorIdImpl(EspRecord* r)
{
    if (!r) return nullptr;
    thread_local std::string buffer;
    buffer = r->EditorID;
    return buffer.c_str();
}
static uint32_t GetRecordFlagsImpl(EspRecord* r) { return r ? r->Flags : 0; }
static int GetRecordIndexImpl(EspRecord* r) { return r ? r->Index : 0; }
static int GetSubRecordCountImpl(EspRecord* r) { return r ? (int)r->SubRecords.size() : 0; }

static int GetSubRecordOccurrenceIndexImpl(const SubRecordData* s) { return s ? s->OccurrenceIndex : -1; }
static int GetSubRecordIndexImpl(const SubRecordData* s) { return s ? s->Index : -1; }
static int GetSubRecordDSDIndexImpl(const SubRecordData* s) { return s ? s->DSDIndex : -1; }

static const char* GetSubRecordSigImpl(const SubRecordData* s) { return s ? s->Sig.c_str() : nullptr; }
static const char* GetSubRecordStringImpl(const SubRecordData* s)
{
    if (!s) return nullptr;
    thread_local std::string buffer;
    buffer = s->GetString();
    return buffer.c_str();
}
static bool IsSubRecordLocalizedImpl(const SubRecordData* s) { return s ? s->IsLocalized : false; }
static uint32_t GetSubRecordStringIdImpl(const SubRecordData* s) { return s ? s->StringID : 0; }
static int GetSubRecordDataSizeImpl(const SubRecordData* s) { return s ? (int)s->Data.size() : 0; }
static bool GetSubRecordDataImpl(const SubRecordData* s, uint8_t* b, int bs)
{
    if (!s || !b) return false; if (bs < (int)s->Data.size()) return false;
    std::memcpy(b, s->Data.data(), s->Data.size()); return true;
}
static int GetSubRecordStringUtf8Impl(const SubRecordData* s, uint8_t* b, int bs)
{
    if (!s) return -1; std::string str = s->GetString(); int l = (int)strlen(str.c_str());
    if (b && bs > l) std::memcpy(b, str.c_str(), l + 1); return l;
}
static int GetSubRecordSigUtf8Impl(const SubRecordData* s, uint8_t* b, int bs)
{
    if (!s) return -1; int l = (int)s->Sig.size();
    if (b && bs > l) { std::memcpy(b, s->Sig.c_str(), l); b[l] = 0; } return l;
}

// Modify
static int ModifySubRecordByOffsetImpl(EspInstance* h, int IsCell, int RecordOffset, int SubOffset, const char* NewUtf8Data)
{
    if (!h || !h->Data) return false;
    std::vector<EspRecord>& Records = (IsCell == 1) ? h->Data->CellRecords : h->Data->Records;
    if (RecordOffset < 0 || RecordOffset >= (int)Records.size()) return false;
    EspRecord& Rec = Records[RecordOffset];
    if (SubOffset < 0 || SubOffset >= (int)Rec.SubRecords.size()) return false;
    SubRecordData& Sub = Rec.SubRecords[SubOffset];
    if (NewUtf8Data)
    {
        if (Sub.StringID <= 0)
        {
            int len = (int)std::strlen(NewUtf8Data);
            Sub.Data.resize(len + 1);
            std::memcpy(Sub.Data.data(), NewUtf8Data, len);
            Sub.Data[len] = '\0';
            Sub.IsModify = true;

            return RESULT_OK;
        }
        else
        {
            //Modifying records containing stringIDs is prohibited.
            return RESULT_REJECTED;
        }
    }
    else
    {
        return RESULT_ERROR;
    }
}

static int ModifySubRecordImpl(EspInstance* h, int IsCell,uint32_t FormID, const char* RecordSig, const char* SubSig,
    int OccurrenceIndex, int Index, const char* NewUtf8Data)
{
    if (!h || !h->Data) return false;
    std::string strRec = RecordSig ? RecordSig : "";
    std::string strSub = SubSig ? SubSig : "";
    auto modify = [&](std::vector<EspRecord>& recs) -> int {
        for (auto& Rec : recs)
        {
            if (Rec.FormID == FormID && Rec.Sig == strRec)
            {
                for (auto& Sub : Rec.SubRecords)
                {
                    if (Sub.Sig == strSub && Sub.OccurrenceIndex == OccurrenceIndex && Sub.Index == Index)
                    {
                        if (NewUtf8Data)
                        {
                            if (Sub.StringID <= 0)
                            {
                                int len = (int)std::strlen(NewUtf8Data);
                                Sub.Data.resize(len + 1);
                                std::memcpy(Sub.Data.data(), NewUtf8Data, len);
                                Sub.Data[len] = '\0';
                                Sub.IsModify = true;

                                return RESULT_OK;
                            }
                            else
                            {
                                //Modifying records containing stringIDs is prohibited.
                                return RESULT_REJECTED;
                            }
                        }
                        else
                        {
                            return RESULT_ERROR;
                        }
                    }
                }  
            }
        }
        
        return RESULT_NOT_FOUND;
        };

        if (IsCell == 1)
        {
            return modify(h->Data->CellRecords);
        }
        else
        {
            return modify(h->Data->Records);
        }

        return RESULT_NOT_FOUND;
}

// Character tracker
static void ClearCharacterTrackerImpl(EspInstance* h)
{
    if (!h) return;
    if (h->CharTracker) h->CharTracker->ClearAll();
    h->CharacterIndexCache.clear();
    h->CharacterCacheDirty = true;
}
static int GetCharacterCountImpl(EspInstance* h) { EnsureCharacterCache(h); return (int)h->CharacterIndexCache.size(); }
static uint32_t GetCharacterFormIdImpl(EspInstance* h, int i)
{
    const CharacterRecord* record = GetCharacterAt(h, i);
    return record ? record->NpcFormID : 0;
}

static int GetCharacterNameImpl(EspInstance* h, int i, uint8_t* b, int bs)
{
    const CharacterRecord* record = GetCharacterAt(h, i);
    return record ? WriteStringToBuffer(record->Name, b, bs) : -1;
}

static int GetCharacterEditorIdImpl(EspInstance* h, int i, uint8_t* b, int bs)
{
    const CharacterRecord* record = GetCharacterAt(h, i);
    return record ? WriteStringToBuffer(record->EditorID, b, bs) : -1;
}

static int GetCharacterVoiceTypeImpl(EspInstance* h, int i, uint8_t* b, int bs)
{
    const CharacterRecord* record = GetCharacterAt(h, i);
    return record ? WriteStringToBuffer(record->VoiceType, b, bs) : -1;
}
static int GetCharacterGenderImpl(EspInstance* h, int i) {
    const CharacterRecord* r = GetCharacterAt(h, i); if (!r) return 0;
    switch (r->Gender) { case CharacterGender::Male: return 1; case CharacterGender::Female: return 2; default: return 0; }
}
static int GetCharacterLinkedInfoCountImpl(EspInstance* h, int i)
{
    const CharacterRecord* record = GetCharacterAt(h, i);
    return record ? static_cast<int>(record->LinkedInfos.size()) : 0;
}

static uint32_t GetCharacterLinkedInfoImpl(EspInstance* h, int i, int li)
{
    const CharacterRecord* record = GetCharacterAt(h, i);
    if (!record || li < 0 || li >= static_cast<int>(record->LinkedInfos.size())) return 0;
    return record->LinkedInfos[static_cast<std::size_t>(li)];
}

static int GetCharacterLinkedFactionCountImpl(EspInstance* h, int i)
{
    const CharacterRecord* record = GetCharacterAt(h, i);
    return record ? static_cast<int>(record->LinkedFactions.size()) : 0;
}

static uint32_t GetCharacterLinkedFactionImpl(EspInstance* h, int i, int li)
{
    const CharacterRecord* record = GetCharacterAt(h, i);
    if (!record || li < 0 || li >= static_cast<int>(record->LinkedFactions.size())) return 0;
    return record->LinkedFactions[static_cast<std::size_t>(li)];
}

static int GetCharacterLinkedRaceCountImpl(EspInstance* h, int i)
{
    const CharacterRecord* record = GetCharacterAt(h, i);
    return record ? static_cast<int>(record->LinkedRaces.size()) : 0;
}

static uint32_t GetCharacterLinkedRaceImpl(EspInstance* h, int i, int li)
{
    const CharacterRecord* record = GetCharacterAt(h, i);
    if (!record || li < 0 || li >= static_cast<int>(record->LinkedRaces.size())) return 0;
    return record->LinkedRaces[static_cast<std::size_t>(li)];
}

static int GetCharacterLinkedVoiceTypeCountImpl(EspInstance* h, int i)
{
    const CharacterRecord* record = GetCharacterAt(h, i);
    return record ? static_cast<int>(record->LinkedVoiceTypes.size()) : 0;
}

static uint32_t GetCharacterLinkedVoiceTypeImpl(EspInstance* h, int i, int li)
{
    const CharacterRecord* record = GetCharacterAt(h, i);
    if (!record || li < 0 || li >= static_cast<int>(record->LinkedVoiceTypes.size())) return 0;
    return record->LinkedVoiceTypes[static_cast<std::size_t>(li)];
}

namespace
{
    struct AbiErrorState
    {
        EspReaderStatus Status = ESP_READER_STATUS_OK;
        char Message[256]{};
    };

    thread_local AbiErrorState LastAbiError;

    void ClearAbiError() noexcept
    {
        LastAbiError.Status = ESP_READER_STATUS_OK;
        LastAbiError.Message[0] = '\0';
    }

    void SetAbiError(EspReaderStatus status, const char* message) noexcept
    {
        LastAbiError.Status = status;
        const std::size_t length = (std::min)(std::strlen(message), sizeof(LastAbiError.Message) - 1);
        std::memcpy(LastAbiError.Message, message, length);
        LastAbiError.Message[length] = '\0';
    }

    void CaptureAbiException() noexcept
    {
        try
        {
            throw;
        }
        catch (const std::bad_alloc&)
        {
            SetAbiError(ESP_READER_STATUS_OUT_OF_MEMORY, "EspReader could not allocate required memory.");
        }
        catch (const std::invalid_argument&)
        {
            SetAbiError(ESP_READER_STATUS_INVALID_ARGUMENT, "EspReader rejected an invalid argument.");
        }
        catch (const std::out_of_range&)
        {
            SetAbiError(ESP_READER_STATUS_OUT_OF_RANGE, "EspReader rejected an out-of-range value.");
        }
        catch (const std::ios_base::failure&)
        {
            SetAbiError(ESP_READER_STATUS_IO_ERROR, "EspReader encountered an input or output error.");
        }
        catch (const std::exception&)
        {
            SetAbiError(ESP_READER_STATUS_INTERNAL_ERROR, "EspReader encountered an internal error.");
        }
        catch (...)
        {
            SetAbiError(ESP_READER_STATUS_INTERNAL_ERROR, "EspReader encountered an unknown internal error.");
        }
    }

    template<typename TResult, typename TAction>
    TResult InvokeAbi(TResult failureValue, TAction&& action) noexcept
    {
        try
        {
            ClearAbiError();
            return action();
        }
        catch (...)
        {
            CaptureAbiException();
            return failureValue;
        }
    }

    template<typename TAction>
    void InvokeAbi(TAction&& action) noexcept
    {
        try
        {
            ClearAbiError();
            action();
        }
        catch (...)
        {
            CaptureAbiException();
        }
    }
}

uint32_t ESP_READER_CALL C_GetAbiVersion(void) noexcept
{
    return ESP_READER_ABI_VERSION;
}

EspReaderStatus ESP_READER_CALL C_GetLastStatus(void) noexcept
{
    return LastAbiError.Status;
}

int32_t ESP_READER_CALL C_GetLastErrorUtf8(uint8_t* buffer, int32_t bufferSize) noexcept
{
    const std::size_t length = std::strlen(LastAbiError.Message);
    if (length > static_cast<std::size_t>((std::numeric_limits<int32_t>::max)()))
        return -1;
    if (buffer != nullptr && bufferSize > static_cast<int32_t>(length))
        std::memcpy(buffer, LastAbiError.Message, length + 1);
    return static_cast<int32_t>(length);
}

#define ESP_READER_WRAP_CDECL(returnType, name, implementation, failureValue, parameters, arguments) \
    returnType ESP_READER_CALL name parameters noexcept \
    { \
        return InvokeAbi<returnType>(failureValue, [&]() -> returnType { return implementation arguments; }); \
    }

#define ESP_READER_WRAP_STDCALL(returnType, name, implementation, failureValue, parameters, arguments) \
    returnType ESP_READER_DIALOG_CALL name parameters noexcept \
    { \
        return InvokeAbi<returnType>(failureValue, [&]() -> returnType { return implementation arguments; }); \
    }

#define ESP_READER_WRAP_VOID_CDECL(name, implementation, parameters, arguments) \
    void ESP_READER_CALL name parameters noexcept \
    { \
        InvokeAbi([&]() { implementation arguments; }); \
    }

#define ESP_READER_WRAP_VOID_STDCALL(name, implementation, parameters, arguments) \
    void ESP_READER_DIALOG_CALL name parameters noexcept \
    { \
        InvokeAbi([&]() { implementation arguments; }); \
    }

ESP_READER_WRAP_CDECL(
    EspInstance*, C_CreateInstance, CreateInstanceImpl, nullptr, (void), ())
ESP_READER_WRAP_VOID_CDECL(
    C_DestroyInstance, DestroyInstanceImpl, (EspInstance* handle), (handle))
ESP_READER_WRAP_CDECL(
    const char*, C_GetVersion, GetVersionImpl, nullptr, (void), ())
ESP_READER_WRAP_CDECL(
    int32_t, C_GetVersionLength, GetVersionLengthImpl, -1, (void), ())
ESP_READER_WRAP_CDECL(
    int32_t, C_SetSkyrimFilter, SetSkyrimFilterImpl, -1, (EspInstance* handle), (handle))
ESP_READER_WRAP_VOID_CDECL(
    C_ClearFilter, ClearFilterImpl, (EspInstance* handle), (handle))
ESP_READER_WRAP_VOID_CDECL(
    C_Clear, ClearImpl, (EspInstance* handle), (handle))
ESP_READER_WRAP_CDECL(
    const char*, C_GetFieldReport, GetFieldReportImpl, nullptr, (EspInstance* handle), (handle))
ESP_READER_WRAP_CDECL(
    int32_t, C_GetFieldReportLength, GetFieldReportLengthImpl, -1, (EspInstance* handle), (handle))
ESP_READER_WRAP_VOID_CDECL(
    FreeSearchResults, FreeSearchResultsImpl, (EspRecord** records, int32_t count), (records, count))
ESP_READER_WRAP_CDECL(
    int32_t, C_GetRecordSig, GetRecordSigImpl, -1,
    (EspRecord* record, uint8_t* buffer, int32_t bufferSize), (record, buffer, bufferSize))
ESP_READER_WRAP_CDECL(
    uint32_t, C_GetRecordFormID, GetRecordFormIdImpl, 0, (EspRecord* record), (record))
ESP_READER_WRAP_CDECL(
    const char*, C_GetRecordEditorID, GetRecordEditorIdImpl, nullptr, (EspRecord* record), (record))
ESP_READER_WRAP_CDECL(
    uint32_t, C_GetRecordFlags, GetRecordFlagsImpl, 0, (EspRecord* record), (record))
ESP_READER_WRAP_CDECL(
    int32_t, C_GetRecordIndex, GetRecordIndexImpl, -1, (EspRecord* record), (record))
ESP_READER_WRAP_CDECL(
    int32_t, C_GetSubRecordCount, GetSubRecordCountImpl, -1, (EspRecord* record), (record))
ESP_READER_WRAP_CDECL(
    const SubRecordData*, C_GetSubRecordData_Ptr, GetSubRecordDataPtrImpl, nullptr,
    (EspRecord* record, int32_t index), (record, index))
ESP_READER_WRAP_CDECL(
    int32_t, C_SubRecordData_GetOccurrenceIndex, GetSubRecordOccurrenceIndexImpl, -1,
    (const SubRecordData* subRecord), (subRecord))
ESP_READER_WRAP_CDECL(
    int32_t, C_SubRecordData_GetIndex, GetSubRecordIndexImpl, -1,
    (const SubRecordData* subRecord), (subRecord))

    ESP_READER_WRAP_CDECL(
    int32_t,C_SubRecordData_GetDSDIndex,GetSubRecordDSDIndexImpl,           -1,                                 
    (const SubRecordData* subRecord), (subRecord))

ESP_READER_WRAP_CDECL(
    const char*, C_SubRecordData_GetSig, GetSubRecordSigImpl, nullptr,
    (const SubRecordData* subRecord), (subRecord))
ESP_READER_WRAP_CDECL(
    const char*, C_SubRecordData_GetString, GetSubRecordStringImpl, nullptr,
    (const SubRecordData* subRecord), (subRecord))
ESP_READER_WRAP_CDECL(
    EspReaderBool, C_SubRecordData_IsLocalized, IsSubRecordLocalizedImpl, 0,
    (const SubRecordData* subRecord), (subRecord))
ESP_READER_WRAP_CDECL(
    uint32_t, C_SubRecordData_GetStringID, GetSubRecordStringIdImpl, 0,
    (const SubRecordData* subRecord), (subRecord))
ESP_READER_WRAP_CDECL(
    int32_t, C_SubRecordData_GetDataSize, GetSubRecordDataSizeImpl, -1,
    (const SubRecordData* subRecord), (subRecord))
ESP_READER_WRAP_CDECL(
    EspReaderBool, C_SubRecordData_GetData, GetSubRecordDataImpl, 0,
    (const SubRecordData* subRecord, uint8_t* buffer, int32_t bufferSize),
    (subRecord, buffer, bufferSize))
ESP_READER_WRAP_CDECL(
    int32_t, C_SubRecordData_GetStringUtf8, GetSubRecordStringUtf8Impl, -1,
    (const SubRecordData* subRecord, uint8_t* buffer, int32_t bufferSize),
    (subRecord, buffer, bufferSize))
ESP_READER_WRAP_CDECL(
    int32_t, C_SubRecordData_GetSigUtf8, GetSubRecordSigUtf8Impl, -1,
    (const SubRecordData* subRecord, uint8_t* buffer, int32_t bufferSize),
    (subRecord, buffer, bufferSize))
ESP_READER_WRAP_CDECL(
    int32_t, C_ModifySubRecordByOffset, ModifySubRecordByOffsetImpl, 0,
    (EspInstance* handle, int32_t isCell, int32_t recordOffset, int32_t subOffset, const char* newUtf8Data),
    (handle, isCell, recordOffset, subOffset, newUtf8Data))
ESP_READER_WRAP_CDECL(
        int32_t, C_ModifySubRecord, ModifySubRecordImpl, 0,
        (EspInstance* handle, int isCell, uint32_t formId, const char* recordSig, const char* subSig,
            int32_t occurrenceIndex, int32_t globalIndex, const char* newUtf8Data),
        (handle, isCell, formId, recordSig, subSig, occurrenceIndex, globalIndex, newUtf8Data))
ESP_READER_WRAP_VOID_CDECL(
    C_ClearCharacterTracker, ClearCharacterTrackerImpl, (EspInstance* handle), (handle))
ESP_READER_WRAP_CDECL(
    uint32_t, C_GetCharacterFormID, GetCharacterFormIdImpl, 0,
    (EspInstance* handle, int32_t index), (handle, index))
ESP_READER_WRAP_CDECL(
    int32_t, C_GetCharacterName, GetCharacterNameImpl, -1,
    (EspInstance* handle, int32_t index, uint8_t* buffer, int32_t bufferSize),
    (handle, index, buffer, bufferSize))
ESP_READER_WRAP_CDECL(
    int32_t, C_GetCharacterEditorID, GetCharacterEditorIdImpl, -1,
    (EspInstance* handle, int32_t index, uint8_t* buffer, int32_t bufferSize),
    (handle, index, buffer, bufferSize))
ESP_READER_WRAP_CDECL(
    int32_t, C_GetCharacterVoiceType, GetCharacterVoiceTypeImpl, -1,
    (EspInstance* handle, int32_t index, uint8_t* buffer, int32_t bufferSize),
    (handle, index, buffer, bufferSize))
ESP_READER_WRAP_CDECL(
    int32_t, C_GetCharacterGender, GetCharacterGenderImpl, 0,
    (EspInstance* handle, int32_t index), (handle, index))
ESP_READER_WRAP_CDECL(
    int32_t, C_GetCharacterLinkedInfoCount, GetCharacterLinkedInfoCountImpl, -1,
    (EspInstance* handle, int32_t index), (handle, index))
ESP_READER_WRAP_CDECL(
    uint32_t, C_GetCharacterLinkedInfo, GetCharacterLinkedInfoImpl, 0,
    (EspInstance* handle, int32_t index, int32_t linkIndex), (handle, index, linkIndex))
ESP_READER_WRAP_CDECL(
    int32_t, C_GetCharacterLinkedFactionCount, GetCharacterLinkedFactionCountImpl, -1,
    (EspInstance* handle, int32_t index), (handle, index))
ESP_READER_WRAP_CDECL(
    uint32_t, C_GetCharacterLinkedFaction, GetCharacterLinkedFactionImpl, 0,
    (EspInstance* handle, int32_t index, int32_t linkIndex), (handle, index, linkIndex))
ESP_READER_WRAP_CDECL(
    int32_t, C_GetCharacterLinkedRaceCount, GetCharacterLinkedRaceCountImpl, -1,
    (EspInstance* handle, int32_t index), (handle, index))
ESP_READER_WRAP_CDECL(
    uint32_t, C_GetCharacterLinkedRace, GetCharacterLinkedRaceImpl, 0,
    (EspInstance* handle, int32_t index, int32_t linkIndex), (handle, index, linkIndex))
ESP_READER_WRAP_CDECL(
    int32_t, C_GetCharacterLinkedVoiceTypeCount, GetCharacterLinkedVoiceTypeCountImpl, -1,
    (EspInstance* handle, int32_t index), (handle, index))
ESP_READER_WRAP_CDECL(
    uint32_t, C_GetCharacterLinkedVoiceType, GetCharacterLinkedVoiceTypeImpl, 0,
    (EspInstance* handle, int32_t index, int32_t linkIndex), (handle, index, linkIndex))
ESP_READER_WRAP_STDCALL(
    C_LinkDIAL, C_GetDialContext, GetDialContextImpl, C_LinkDIAL{},
    (EspInstance* handle, int32_t recordOffset, int32_t subOffset),
    (handle, recordOffset, subOffset))
ESP_READER_WRAP_STDCALL(
    C_LinkDIAL, C_GetDialContextByDial, GetDialContextByDialImpl, C_LinkDIAL{},
    (EspInstance* handle, int32_t recordOffset), (handle, recordOffset))
ESP_READER_WRAP_VOID_STDCALL(
    C_FreeDialContext, FreeDialContextImpl, (C_LinkDIAL* context), (context))
ESP_READER_WRAP_CDECL(
    int32_t, C_GetTitleIndexByBookDesc, GetTitleIndexByBookDescImpl, -1,
    (EspInstance* handle, int32_t recordOffset, int32_t descSubOffset),
    (handle, recordOffset, descSubOffset))
ESP_READER_WRAP_CDECL(
    int32_t, C_GetDescIndexByBookTitle, GetDescIndexByBookTitleImpl, -1,
    (EspInstance* handle, int32_t recordOffset, int32_t descSubOffset),
    (handle, recordOffset, descSubOffset))

void ESP_READER_CALL C_InitFilter(EspInstance* handle) noexcept
{
    InvokeAbi([&]()
    {
        if (handle == nullptr)
        {
            SetAbiError(ESP_READER_STATUS_INVALID_ARGUMENT, "The EspReader handle is null.");
            return;
        }
        InitFilterImpl(handle);
    });
}

int32_t ESP_READER_CALL C_GetFilter(EspInstance* handle, uint8_t* buffer, int32_t bufferSize) noexcept
{
    return InvokeAbi<int32_t>(-1, [&]()
    {
        if (handle == nullptr || handle->Filter == nullptr || bufferSize < 0)
        {
            SetAbiError(ESP_READER_STATUS_INVALID_ARGUMENT, "The filter request is invalid.");
            return -1;
        }
        const int32_t length = GetFilterImpl(handle, buffer, bufferSize);
        if (buffer != nullptr && bufferSize <= length)
            SetAbiError(ESP_READER_STATUS_BUFFER_TOO_SMALL, "The filter buffer is too small.");
        return length;
    });
}

int32_t ESP_READER_CALL C_SetFilter(
    EspInstance* handle,
    const char* parentSig,
    const char** childSigs,
    int32_t childCount) noexcept
{
    return InvokeAbi<int32_t>(-1, [&]()
    {
        if (handle == nullptr || handle->Filter == nullptr || parentSig == nullptr || childCount < 0 ||
            (childCount > 0 && childSigs == nullptr))
        {
            SetAbiError(ESP_READER_STATUS_INVALID_ARGUMENT, "The filter configuration is invalid.");
            return -1;
        }
        for (int32_t index = 0; index < childCount; ++index)
        {
            if (childSigs[index] == nullptr)
            {
                SetAbiError(ESP_READER_STATUS_INVALID_ARGUMENT, "A child signature is null.");
                return -1;
            }
        }
        return SetFilterImpl(handle, parentSig, childSigs, childCount);
    });
}

int32_t ESP_READER_CALL C_ReadEsp(EspInstance* handle, const wchar_t* espPath) noexcept
{
    return InvokeAbi<int32_t>(1, [&]()
    {
        if (handle == nullptr || espPath == nullptr)
        {
            SetAbiError(ESP_READER_STATUS_INVALID_ARGUMENT, "The EspReader handle or UTF-16 path is null.");
            return -1;
        }
        const int32_t result = ReadEspImpl(handle, espPath);
        if (result != 0)
            SetAbiError(ESP_READER_STATUS_PARSE_ERROR, "The plugin could not be opened or parsed.");
        return result;
    });
}

int32_t ESP_READER_CALL C_SaveEsp(EspInstance* handle, const char* utf8Path) noexcept
{
    return InvokeAbi<int32_t>(0, [&]() -> int32_t
    {
        if (handle == nullptr || utf8Path == nullptr)
        {
            SetAbiError(ESP_READER_STATUS_INVALID_ARGUMENT, "The EspReader handle or UTF-8 path is null.");
            return 0;
        }

        const int32_t result = SaveEspImpl(handle, utf8Path);

        if (result < 0)
            SetAbiError(ESP_READER_STATUS_IO_ERROR, "The plugin could not be saved.");

        return result;
    });
}

EspRecord** ESP_READER_CALL C_SearchBySig(
    EspInstance* handle,
    const char* parentSig,
    const char* childSig,
    int32_t* outCount) noexcept
{
    return InvokeAbi<EspRecord**>(nullptr, [&]()
    {
        if (outCount == nullptr)
        {
            SetAbiError(ESP_READER_STATUS_INVALID_ARGUMENT, "The search count pointer is null.");
            return static_cast<EspRecord**>(nullptr);
        }
        *outCount = 0;
        if (handle == nullptr || parentSig == nullptr)
        {
            SetAbiError(ESP_READER_STATUS_INVALID_ARGUMENT, "The search handle or parent signature is null.");
            return static_cast<EspRecord**>(nullptr);
        }
        return SearchBySigImpl(handle, parentSig, childSig, outCount);
    });
}

int32_t ESP_READER_CALL C_GetCharacterCount(EspInstance* handle) noexcept
{
    return InvokeAbi<int32_t>(-1, [&]()
    {
        if (handle == nullptr)
        {
            SetAbiError(ESP_READER_STATUS_INVALID_ARGUMENT, "The EspReader handle is null.");
            return -1;
        }
        return GetCharacterCountImpl(handle);
    });
}

#undef ESP_READER_WRAP_CDECL
#undef ESP_READER_WRAP_STDCALL
#undef ESP_READER_WRAP_VOID_CDECL
#undef ESP_READER_WRAP_VOID_STDCALL

BOOL APIENTRY DllMain(HMODULE, DWORD, LPVOID) { return TRUE; }

// ============================================================
//  Test main (optional, can be removed)
// ============================================================
#ifdef _DEBUG
int main()
{
    SetConsoleOutputCP(CP_UTF8);

    EspInstance* instance = C_CreateInstance();
    if (!instance)
    {
        std::cerr << "Failed to create EspInstance\n";
        return -1;
    }

    C_InitFilter(instance);
    C_SetSkyrimFilter(instance);

    std::wcout << L"Starting ESP parsing...\n";

    const wchar_t* espPath =
        L"E:\\Interesting NPCs - 4.5 to 4.54 Update-29194-4-54-1681353795\\Data\\3DNPC.esp";

    int state = C_ReadEsp(instance, espPath);

    std::wstring wPath = L"E:\\Interesting NPCs - 4.5 to 4.54 Update-29194-4-54-1681353795\\Data\\Test3DNPC.esp";
    int len = WideCharToMultiByte(CP_UTF8, 0, wPath.c_str(), -1, NULL, 0, NULL, NULL);
    std::string utf8Path(len, 0);
    WideCharToMultiByte(CP_UTF8, 0, wPath.c_str(), -1, &utf8Path[0], len, NULL, NULL);
    utf8Path.pop_back();

    int result = SaveEsp_Inst(instance, utf8Path.c_str());
    std::cout << "Save result: " << (result ? "true" : "false") << "\n";

    if (state == 0)
    {
        if (!instance->Data->Records.empty())
        {
            for (size_t i = 0; i < instance->Data->Records.size(); ++i)
            {
                auto& rec = instance->Data->Records[i];
                if (rec.Sig == "INFO" && !rec.LocalDialogues.empty())
                {
                    int recOff = (int)i;
                    int subOff = rec.LocalDialogues[0].SubOffset;
                    C_LinkDIAL ctx = C_GetDialContext(instance, recOff, subOff);
                    if (ctx.HasData)
                    {
                        std::cout << "Dialogue context found. Head ResponseID: " << ctx.Head.ResponseID << "\n";
                        C_FreeDialContext(&ctx);
                    }
                    break;
                }
            }
        }
    }

    std::cout << "Done.\n";
    C_DestroyInstance(instance);
    return 0;
}
#endif
