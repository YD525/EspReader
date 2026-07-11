#include <fstream>
#include <vector>
#include <string>
#include <iostream>
#include <cstdint>
#include <stack>
#include <unordered_map>
#include <unordered_set>
#include "miniz.h"
#include <random>
#include <mutex>

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#ifdef SSELexApi_EXPORTS
#define SSELex_API __declspec(dllexport)
#else
#define SSELex_API __declspec(dllimport)
#endif


#include "EspRecord.cpp"

class EspInstance
{
public:
    ESP_HeuristicAnalysis* TextValidator = nullptr;
    CharacterTracker* CharTracker = nullptr;
    EspData* Data = nullptr;
    RecordFilter* Filter = nullptr;
    std::wstring            LastSetPath;

    // Character index cache
    std::vector<const CharacterRecord*> CharacterIndexCache;
    bool                    CharacterCacheDirty = true;

    // Deferred link maps
    std::unordered_map<uint32_t, std::vector<uint32_t>> DeferredInfoLinks;
    std::unordered_map<uint32_t, std::vector<uint32_t>> DeferredVoiceTypeLinks;
    std::unordered_map<uint32_t, std::vector<uint32_t>> DeferredFactionLinks;
    std::unordered_map<uint32_t, std::vector<uint32_t>> DeferredRaceLinks;

    EspInstance()
    {
        TextValidator = new ESP_HeuristicAnalysis();
        CharTracker = new CharacterTracker();
        Filter = new RecordFilter();
    }

    ~EspInstance() { ReleaseAll(); }

    void ReleaseAll()
    {
        delete TextValidator; TextValidator = nullptr;
        delete CharTracker;   CharTracker = nullptr;
        delete Data;          Data = nullptr;
        delete Filter;        Filter = nullptr;

        CharacterIndexCache.clear();
        CharacterCacheDirty = true;
        DeferredInfoLinks.clear();
        DeferredVoiceTypeLinks.clear();
        DeferredFactionLinks.clear();
        DeferredRaceLinks.clear();
        LastSetPath.clear();
    }

    // Reset data only (keep filter/validator alive)
    void ClearData()
    {
        delete Data; Data = nullptr;

        CharacterIndexCache.clear();
        CharacterCacheDirty = true;
        DeferredInfoLinks.clear();
        DeferredVoiceTypeLinks.clear();
        DeferredFactionLinks.clear();
        DeferredRaceLinks.clear();
        LastSetPath.clear();
    }
};

// ============================================================
//  Version string
// ============================================================
static const std::string Version = "1.6.8";

// ============================================================
//  Forward declarations (parsing helpers – unchanged logic)
// ============================================================
#pragma pack(push,1)
struct RecordHeader {
    char     Sig[4];
    uint32_t DataSize;
    uint32_t Flags;
    uint32_t FormID;
    uint32_t VersionCtrl;
    uint16_t Version;
    uint16_t Unknown;
};
#pragma pack(pop)

#pragma pack(push,1)
struct GroupHeader {
    char     Sig[4];
    uint32_t Size;
    char     Label[4];
    uint32_t GroupType;
    uint32_t Stamp;
    uint32_t Unknown;
};
#pragma pack(pop)

#pragma pack(push,1)
struct SubRecordHeader {
    char     Sig[4];
    uint16_t Size;
};
#pragma pack(pop)

constexpr uint32_t RECORD_FLAG_COMPRESSED = 0x00040000;
constexpr uint32_t RECORD_FLAG_LOCALIZED = 0x00000080; // TES4 header only

template<typename T>
inline void Read(std::ifstream& f, T& out) { f.read(reinterpret_cast<char*>(&out), sizeof(T)); }
inline bool IsGRUP(const char sig[4]) { return std::memcmp(sig, "GRUP", 4) == 0; }
inline bool IsCompressed(const RecordHeader& hdr) { return (hdr.Flags & RECORD_FLAG_COMPRESSED) != 0; }

bool ZlibDecompress(const uint8_t* src, size_t srcSize, std::vector<uint8_t>& out, size_t uncompressedSize)
{
    out.resize(uncompressedSize);
    size_t ret = tinfl_decompress_mem_to_mem(out.data(), uncompressedSize, src, srcSize, TINFL_FLAG_PARSE_ZLIB_HEADER);
    return ret == uncompressedSize;
}

bool ZlibCompress(const uint8_t* src, size_t srcSize, std::vector<uint8_t>& out)
{
    mz_ulong destLen = compressBound(srcSize);
    out.resize(destLen);
    int ret = compress2(out.data(), &destLen, src, srcSize, Z_BEST_COMPRESSION);
    if (ret != Z_OK) return false;
    out.resize(destLen);
    return true;
}

// ============================================================
//  Parsing helpers  (take EspInstance* instead of globals)
// ============================================================
void ParseSubRecords(EspInstance* Instance, const uint8_t* data, size_t dataSize, EspRecord& rec,
    const RecordFilter& filter, const char recordSig[4])
{
    rec.OnRecordBegin();
    size_t offset = 0;
    while (offset + sizeof(SubRecordHeader) <= dataSize)
    {
        const SubRecordHeader* sub = reinterpret_cast<const SubRecordHeader*>(data + offset);
        if (offset + sizeof(SubRecordHeader) + sub->Size > dataSize) break;
        rec.AddSubRecord(
            Instance->CharTracker,
            Instance->TextValidator
            , sub->Sig, data + offset + sizeof(SubRecordHeader), sub->Size,
            const_cast<RecordFilter&>(filter));
        offset += sizeof(SubRecordHeader) + sub->Size;
    }
    rec.OnRecordFinished(
        Instance->CharTracker,
        &Instance->DeferredInfoLinks,
        &Instance->DeferredVoiceTypeLinks,
        &Instance->DeferredFactionLinks,
        &Instance->DeferredRaceLinks
        , recordSig, nullptr, 0);
}

void ParseSubRecordsStream(EspInstance* Instance, std::ifstream& f, uint32_t recordSize, EspRecord& rec,
    const RecordFilter& filter, const char recordSig[4])
{
    rec.OnRecordBegin();
    uint32_t bytesRead = 0;
    while (bytesRead < recordSize && f.good())
    {
        if (bytesRead + sizeof(SubRecordHeader) > recordSize) { f.seekg(recordSize - bytesRead, std::ios::cur); break; }
        SubRecordHeader sub{};
        if (!f.read(reinterpret_cast<char*>(&sub), sizeof(sub))) break;
        bytesRead += sizeof(SubRecordHeader);
        if (bytesRead + sub.Size > recordSize) { f.seekg(recordSize - bytesRead, std::ios::cur); break; }
        std::vector<uint8_t> buf(sub.Size);
        if (sub.Size > 0) { f.read(reinterpret_cast<char*>(buf.data()), sub.Size); bytesRead += sub.Size; }
        rec.AddSubRecord(
            Instance->CharTracker,
            Instance->TextValidator
            , sub.Sig, buf.data(), sub.Size, const_cast<RecordFilter&>(filter));
    }
    rec.OnRecordFinished(
        Instance->CharTracker,
        &Instance->DeferredInfoLinks,
        &Instance->DeferredVoiceTypeLinks,
        &Instance->DeferredFactionLinks,
        &Instance->DeferredRaceLinks
        , recordSig, nullptr, 0);
}

// ---- Instance-aware versions of the big parse functions ----

static void ParseRecord_Inst(EspInstance* Instance, std::ifstream& f, const char Sig[4], uint32_t CurrentDialFormID)
{
    RecordHeader hdr{};
    std::memcpy(hdr.Sig, Sig, 4);
    Read(f, hdr.DataSize); Read(f, hdr.Flags); Read(f, hdr.FormID);
    Read(f, hdr.VersionCtrl); Read(f, hdr.Version); Read(f, hdr.Unknown);

    //CharacterTracker* CurrentTracker = Instance->CharTracker;

    EspRecord rec(hdr.Sig, hdr.FormID, hdr.Flags);

    if (std::memcmp(hdr.Sig, "TES4", 4) == 0)
    {
        Instance->Filter->FileIsLocalized = (hdr.Flags & RECORD_FLAG_LOCALIZED) != 0;
    }
    if (IsCompressed(hdr))
    {
        if (hdr.DataSize < 4) { f.seekg(hdr.DataSize, std::ios::cur); Instance->Data->AddRecord(rec, *Instance->Filter, CurrentDialFormID); return; }
        uint32_t uncompressedSize = 0; Read(f, uncompressedSize);
        uint32_t compressedSize = hdr.DataSize - 4;
        std::vector<uint8_t> compressed(compressedSize);
        f.read(reinterpret_cast<char*>(compressed.data()), compressedSize);
        std::vector<uint8_t> decompressed;
        if (ZlibDecompress(compressed.data(), compressedSize, decompressed, uncompressedSize))
            ParseSubRecords(Instance, decompressed.data(), decompressed.size(), rec, *Instance->Filter, hdr.Sig);
    }
    else { ParseSubRecordsStream(Instance, f, hdr.DataSize, rec, *Instance->Filter, hdr.Sig); }
    Instance->Data->AddRecord(rec, *Instance->Filter, CurrentDialFormID);
}

static void ParseCellGroup_Inst(EspInstance* Instance, std::ifstream& f, uint32_t groupSize, uint32_t currentDialFormID);

static void ParseGroupIterative_Inst(EspInstance* Instance, std::ifstream& f)
{
    GroupHeader gh{};
    std::memcpy(gh.Sig, "GRUP", 4);
    Read(f, gh.Size); f.read(gh.Label, 4); Read(f, gh.GroupType); Read(f, gh.Stamp); Read(f, gh.Unknown);
    if (gh.Size < 24) return;

    Instance->Data->IncrementGrupCount();

    if (std::memcmp(gh.Label, "CELL", 4) == 0) { ParseCellGroup_Inst(Instance, f, gh.Size - 24, 0); return; }

    struct GS {
        uint32_t remaining;
        uint32_t currentDialFormID;
    };

    std::stack<GS> groupStack;

    uint32_t initialDialFormID = 0;

    groupStack.push({ gh.Size - 24, initialDialFormID });

    while (!groupStack.empty())
    {
        auto& state = groupStack.top();
        if (state.remaining == 0) { groupStack.pop(); continue; }
        if (state.remaining < 4) { f.seekg(state.remaining, std::ios::cur); groupStack.pop(); continue; }

        char sig[4];
        if (!f.read(sig, 4)) { groupStack.pop(); continue; }

        if (IsGRUP(sig))
        {
            if (state.remaining < 24) { f.seekg(state.remaining - 4, std::ios::cur); groupStack.pop(); continue; }
            Read(f, gh.Size); f.read(gh.Label, 4); Read(f, gh.GroupType); Read(f, gh.Stamp); Read(f, gh.Unknown);
            if (gh.Size < 24 || gh.Size > state.remaining) { groupStack.pop(); continue; }
            if (std::memcmp(gh.Label, "CELL", 4) == 0) { ParseCellGroup_Inst(Instance, f, gh.Size - 24, 0); state.remaining -= gh.Size; continue; }
            Instance->Data->IncrementGrupCount();

            uint32_t nextDialFormID = state.currentDialFormID;
            if (gh.GroupType != 0)
            {
                std::memcpy(&nextDialFormID, gh.Label, 4);
            }

            state.remaining -= gh.Size;
            groupStack.push({ gh.Size - 24, nextDialFormID });
        }
        else
        {
            if (state.remaining < 24) { f.seekg(state.remaining - 4, std::ios::cur); groupStack.pop(); continue; }
            RecordHeader hdr{};
            std::memcpy(hdr.Sig, sig, 4);
            Read(f, hdr.DataSize); Read(f, hdr.Flags); Read(f, hdr.FormID); Read(f, hdr.VersionCtrl); Read(f, hdr.Version); Read(f, hdr.Unknown);
            uint32_t recordTotalSize = 24 + hdr.DataSize;
            if (recordTotalSize > state.remaining) { groupStack.pop(); continue; }

            EspRecord Record(hdr.Sig, hdr.FormID, hdr.Flags);

            // === REMOVED: ParentDialFormID assignment (useless) ===
            // No longer set ParentDialFormID or HasDialContext here – they are set during subrecord parsing.

            if (IsCompressed(hdr))
            {
                if (hdr.DataSize < 4) f.seekg(hdr.DataSize, std::ios::cur);
                else {
                    uint32_t uncompressedSize = 0; Read(f, uncompressedSize);
                    uint32_t compressedSize = hdr.DataSize - 4;
                    std::vector<uint8_t> compressed(compressedSize);
                    f.read(reinterpret_cast<char*>(compressed.data()), compressedSize);
                    std::vector<uint8_t> decompressed;
                    if (ZlibDecompress(compressed.data(), compressedSize, decompressed, uncompressedSize))
                        ParseSubRecords(Instance, decompressed.data(), decompressed.size(), Record, *Instance->Filter, hdr.Sig);
                }
            }
            else ParseSubRecordsStream(Instance, f, hdr.DataSize, Record, *Instance->Filter, hdr.Sig);

            if (Record.CheckSub()) Instance->Data->AddRecord(Record, *Instance->Filter, state.currentDialFormID);
            state.remaining -= recordTotalSize;
        }
    }
}

static void ParseCellGroup_Inst(EspInstance* Instance, std::ifstream& f, uint32_t groupSize, uint32_t currentDialFormID)
{
    uint32_t bytesRead = 0;
    while (bytesRead < groupSize && f.good())
    {
        if (groupSize - bytesRead < 4) { f.seekg(groupSize - bytesRead, std::ios::cur); break; }
        char sig[4];
        if (!f.read(sig, 4)) break;
        bytesRead += 4;

        if (IsGRUP(sig))
        {
            if (groupSize - bytesRead < 20) { f.seekg(groupSize - bytesRead, std::ios::cur); break; }
            GroupHeader gh{};
            std::memcpy(gh.Sig, sig, 4);
            Read(f, gh.Size);
            f.read(gh.Label, 4);
            Read(f, gh.GroupType);
            Read(f, gh.Stamp);
            Read(f, gh.Unknown);
            bytesRead += 20;
            if (gh.Size < 24 || gh.Size >(groupSize - bytesRead + 24)) { f.seekg(groupSize - bytesRead, std::ios::cur); break; }
            Instance->Data->IncrementGrupCount();
            uint32_t contentSize = gh.Size - 24;
            ParseCellGroup_Inst(Instance, f, contentSize, currentDialFormID);  //Pass currentDialFormID
            bytesRead += contentSize;
        }
        else
        {
            if (groupSize - bytesRead < 20) { f.seekg(groupSize - bytesRead, std::ios::cur); break; }
            RecordHeader hdr{};
            std::memcpy(hdr.Sig, sig, 4);
            Read(f, hdr.DataSize);
            Read(f, hdr.Flags);
            Read(f, hdr.FormID);
            Read(f, hdr.VersionCtrl);
            Read(f, hdr.Version);
            Read(f, hdr.Unknown);
            bytesRead += 20;
            uint32_t recordTotalSize = hdr.DataSize;
            if (recordTotalSize > (groupSize - bytesRead)) { f.seekg(groupSize - bytesRead, std::ios::cur); break; }

            EspRecord Record(hdr.Sig, hdr.FormID, hdr.Flags);
            if (IsCompressed(hdr))
            {
                if (hdr.DataSize < 4) f.seekg(hdr.DataSize, std::ios::cur);
                else {
                    uint32_t uncompressedSize = 0;
                    Read(f, uncompressedSize);
                    uint32_t compressedSize = hdr.DataSize - 4;
                    std::vector<uint8_t> compressed(compressedSize);
                    f.read(reinterpret_cast<char*>(compressed.data()), compressedSize);
                    std::vector<uint8_t> decompressed;
                    if (ZlibDecompress(compressed.data(), compressedSize, decompressed, uncompressedSize))
                        ParseSubRecords(Instance, decompressed.data(), decompressed.size(), Record, *Instance->Filter, hdr.Sig);
                }
            }
            else ParseSubRecordsStream(Instance, f, hdr.DataSize, Record, *Instance->Filter, hdr.Sig);

            if (Record.CheckSub()) Instance->Data->AddRecord(Record, *Instance->Filter, currentDialFormID);
            bytesRead += recordTotalSize;
        }
    }
    if (bytesRead < groupSize) f.seekg(groupSize - bytesRead, std::ios::cur);
}

// ============================================================
//  Flush deferred links  (instance-local maps)
// ============================================================
static void FlushDeferredInfoLinks_Inst(EspInstance* inst)
{
    if (!inst->CharTracker) return;

    for (auto& kv : inst->DeferredInfoLinks)
    {
        auto it = inst->CharTracker->Characters.find(kv.first);
        if (it != inst->CharTracker->Characters.end())
            for (uint32_t fid : kv.second) it->second.LinkedInfos.push_back(fid);
    }
    for (auto& kv : inst->DeferredVoiceTypeLinks)
    {
        auto vtIt = inst->CharTracker->VoiceTypeToNPC.find(kv.first);
        if (vtIt != inst->CharTracker->VoiceTypeToNPC.end())
        {
            auto chr = inst->CharTracker->Characters.find(vtIt->second);
            if (chr != inst->CharTracker->Characters.end())
                for (uint32_t fid : kv.second) chr->second.LinkedVoiceTypes.push_back(fid);
        }
    }
    for (auto& kv : inst->DeferredFactionLinks)
    {
        auto it = inst->CharTracker->Characters.find(kv.first);
        if (it != inst->CharTracker->Characters.end())
            for (uint32_t fid : kv.second) it->second.LinkedFactions.push_back(fid);
    }
    for (auto& kv : inst->DeferredRaceLinks)
    {
        auto it = inst->CharTracker->Characters.find(kv.first);
        if (it != inst->CharTracker->Characters.end())
            for (uint32_t fid : kv.second) it->second.LinkedRaces.push_back(fid);
    }

    inst->DeferredInfoLinks.clear();
    inst->DeferredVoiceTypeLinks.clear();
    inst->DeferredFactionLinks.clear();
    inst->DeferredRaceLinks.clear();
}

// ============================================================
//  Character cache helpers
// ============================================================
static void EnsureCharacterCache(EspInstance* inst)
{
    if (!inst->CharacterCacheDirty) return;
    inst->CharacterIndexCache.clear();
    if (!inst->CharTracker) return;
    for (const auto& kv : inst->CharTracker->Characters)
        inst->CharacterIndexCache.push_back(&kv.second);
    inst->CharacterCacheDirty = false;
}

static const CharacterRecord* GetCharacterAt(EspInstance* inst, int index)
{
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
static inline uint64_t MakeRecordKey(uint32_t FormID, const std::string& Sig) { return MakeRecordKey(FormID, Sig.c_str()); }

struct OriginalSubRecord { std::string Sig; int OccurrenceIndex; size_t OffsetInData; uint16_t Size; };

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
    size_t offset = 0;
    while (offset + sizeof(SubRecordHeader) <= dataSize)
    {
        const SubRecordHeader* sub = reinterpret_cast<const SubRecordHeader*>(data + offset);
        if (offset + sizeof(SubRecordHeader) + sub->Size > dataSize) break;
        OriginalSubRecord osr;
        osr.Sig = std::string(sub->Sig, 4);
        osr.OccurrenceIndex = occ[osr.Sig]++;
        osr.OffsetInData = offset;
        osr.Size = sub->Size;
        result.push_back(osr);
        offset += sizeof(SubRecordHeader) + sub->Size;
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
        const SubRecordData* modified = FindModifiedSubRecord(modifiedIndex, parentSig, formID, osr.Sig, osr.OccurrenceIndex);
        if (modified)
        {
            if (modified->Data.size() > 0xFFFF) {
                result.insert(result.end(), originalData + osr.OffsetInData, originalData + osr.OffsetInData + sizeof(SubRecordHeader) + osr.Size);
                continue;
            }
            SubRecordHeader newHeader; std::memcpy(newHeader.Sig, osr.Sig.c_str(), 4);
            newHeader.Size = static_cast<uint16_t>(modified->Data.size());
            result.insert(result.end(), reinterpret_cast<uint8_t*>(&newHeader), reinterpret_cast<uint8_t*>(&newHeader) + sizeof(newHeader));
            result.insert(result.end(), modified->Data.begin(), modified->Data.end());
        }
        else result.insert(result.end(), originalData + osr.OffsetInData, originalData + osr.OffsetInData + sizeof(SubRecordHeader) + osr.Size);
    }
    return result;
}

// Forward declare ProcessGRUP_Inst
static bool ProcessGRUP_Inst(std::ifstream& Fin, std::ofstream& Fout, const char Sig[4], const std::unordered_map<uint64_t, const EspRecord*>& idx);
static bool ProcessGRUPContent_Inst(std::ifstream& Fin, std::ofstream& Fout, int64_t ContentSize, const std::unordered_map<uint64_t, const EspRecord*>& idx);

static bool ProcessRecord_Inst(std::ifstream& Fin, std::ofstream& Fout, const char Sig[4],
    const std::unordered_map<uint64_t, const EspRecord*>& modifiedIndex)
{
    RecordHeader HDR{}; std::memcpy(HDR.Sig, Sig, 4);
    Read(Fin, HDR.DataSize); Read(Fin, HDR.Flags); Read(Fin, HDR.FormID); Read(Fin, HDR.VersionCtrl); Read(Fin, HDR.Version); Read(Fin, HDR.Unknown);
    std::vector<uint8_t> OriginalData(HDR.DataSize);
    Fin.read(reinterpret_cast<char*>(OriginalData.data()), HDR.DataSize);

    if (modifiedIndex.find(MakeRecordKey(HDR.FormID, Sig)) == modifiedIndex.end())
    {
        Fout.write(reinterpret_cast<const char*>(&HDR), sizeof(HDR));
        Fout.write(reinterpret_cast<const char*>(OriginalData.data()), HDR.DataSize);
        return true;
    }

    std::vector<uint8_t> WorkingData;
    bool WasCompressed = IsCompressed(HDR);
    if (WasCompressed)
    {
        if (HDR.DataSize < 4) { Fout.write(reinterpret_cast<const char*>(&HDR), sizeof(HDR)); Fout.write(reinterpret_cast<const char*>(OriginalData.data()), HDR.DataSize); return true; }
        uint32_t UncompressedSize; std::memcpy(&UncompressedSize, OriginalData.data(), 4);
        if (!ZlibDecompress(OriginalData.data() + 4, OriginalData.size() - 4, WorkingData, UncompressedSize)) return false;
    }
    else WorkingData = OriginalData;

    WorkingData = ModifySubRecordsWithFilter(WorkingData.data(), WorkingData.size(), std::string(Sig, 4), HDR.FormID, modifiedIndex);

    std::vector<uint8_t> FinalData;
    if (WasCompressed)
    {
        std::vector<uint8_t> Compressed;
        if (!ZlibCompress(WorkingData.data(), WorkingData.size(), Compressed)) return false;
        FinalData.resize(4 + Compressed.size());
        uint32_t UncompSize = static_cast<uint32_t>(WorkingData.size());
        std::memcpy(FinalData.data(), &UncompSize, 4);
        std::memcpy(FinalData.data() + 4, Compressed.data(), Compressed.size());
    }
    else FinalData = WorkingData;

    HDR.DataSize = static_cast<uint32_t>(FinalData.size());
    Fout.write(reinterpret_cast<const char*>(&HDR), sizeof(HDR));
    Fout.write(reinterpret_cast<const char*>(FinalData.data()), FinalData.size());
    return true;
}

static bool ProcessGRUP_Inst(std::ifstream& Fin, std::ofstream& Fout, const char Sig[4],
    const std::unordered_map<uint64_t, const EspRecord*>& idx)
{
    GroupHeader GH{}; std::memcpy(GH.Sig, Sig, 4);
    Read(Fin, GH.Size); Fin.read(GH.Label, 4); Read(Fin, GH.GroupType); Read(Fin, GH.Stamp); Read(Fin, GH.Unknown);

    if (GH.Size < 24) return false;

    std::streampos headerPos = Fout.tellp();
    Fout.write(reinterpret_cast<char*>(&GH), sizeof(GH));
    std::streampos contentStart = Fout.tellp();

    if (!ProcessGRUPContent_Inst(Fin, Fout, GH.Size - 24, idx)) return false;

    std::streampos contentEnd = Fout.tellp();
    uint32_t actualGrupSize = static_cast<uint32_t>(contentEnd - contentStart) + 24;
    if (actualGrupSize != GH.Size)
    {
        std::streampos saved = Fout.tellp();
        Fout.seekp(headerPos + std::streamoff(4));
        Fout.write(reinterpret_cast<char*>(&actualGrupSize), sizeof(actualGrupSize));
        Fout.seekp(saved);
    }
    return true;
}

static bool ProcessGRUPContent_Inst(std::ifstream& Fin, std::ofstream& Fout, int64_t ContentSize,
    const std::unordered_map<uint64_t, const EspRecord*>& idx)
{
    int64_t processed = 0;
    while (processed < ContentSize && Fin.good())
    {
        if (ContentSize - processed < 4) { Fin.seekg(ContentSize - processed, std::ios::cur); processed = ContentSize; break; }
        char Sig[4];
        std::streampos before = Fin.tellg();
        if (!Fin.read(Sig, 4)) break;
        bool ok = IsGRUP(Sig) ? ProcessGRUP_Inst(Fin, Fout, Sig, idx) : ProcessRecord_Inst(Fin, Fout, Sig, idx);
        if (!ok) return false;
        processed += static_cast<int64_t>(static_cast<int64_t>(Fin.tellg()) - static_cast<int64_t>(before));
    }
    if (processed < ContentSize) { Fin.seekg(ContentSize - processed, std::ios::cur); }
    else if (processed > ContentSize) { Fin.seekg(-(processed - ContentSize), std::ios::cur); }
    return true;
}

static bool ProcessFileContent_Inst(std::ifstream& Fin, std::ofstream& Fout,
    const std::unordered_map<uint64_t, const EspRecord*>& idx)
{
    while (Fin.good() && Fin.peek() != EOF)
    {
        char Sig[4]; if (!Fin.read(Sig, 4)) break;
        bool ok = IsGRUP(Sig) ? ProcessGRUP_Inst(Fin, Fout, Sig, idx) : ProcessRecord_Inst(Fin, Fout, Sig, idx);
        if (!ok) return false;
    }
    return true;
}

static std::mutex SaveEspLock;

static bool SaveEsp_Inst(EspInstance* inst, const char* Utf8Path)
{
    std::lock_guard<std::mutex> Lock(SaveEspLock);

    if (!inst || inst->LastSetPath.empty() || !Utf8Path) return false;

    int Wlen = MultiByteToWideChar(CP_UTF8, 0, Utf8Path, -1, NULL, 0);
    if (Wlen == 0) return false;
    std::wstring WSavePath(Wlen - 1, 0);
    MultiByteToWideChar(CP_UTF8, 0, Utf8Path, -1, &WSavePath[0], Wlen);

    if (WSavePath == inst->LastSetPath) return false;

    std::ifstream Fin(inst->LastSetPath, std::ios::binary);
    if (!Fin.is_open()) return false;

    std::ofstream Fout(WSavePath, std::ios::binary);
    if (!Fout.is_open()) { Fin.close(); return false; }

    static char ReadBuf[4 * 1024 * 1024];
    static char WriteBuf[4 * 1024 * 1024];
    Fin.rdbuf()->pubsetbuf(ReadBuf, sizeof(ReadBuf));
    Fout.rdbuf()->pubsetbuf(WriteBuf, sizeof(WriteBuf));

    auto ModifiedIndex = BuildModifiedIndex(inst);
    bool Success = ProcessFileContent_Inst(Fin, Fout, ModifiedIndex);

    Fin.close(); Fout.close();
    return Success;
}

// ============================================================
//  Exported C API  –  every function takes handle as first arg
// ============================================================

// --- New dialogue context structures (lean, for C#) ---
struct C_DialResponseNode
{
    uint32_t ResponseID;
    uint32_t EmotionType;
    int RecordOffset;
    int SubOffset;
};

struct C_LinkDIAL
{
    int HasData;
    C_DialResponseNode Head;
    C_DialResponseNode* Links;
    uint32_t LinkCount;
};

extern "C"
{
    // ── Lifecycle ────────────────────────────────────────────
    SSELex_API EspInstance* C_CreateInstance();
    SSELex_API void         C_DestroyInstance(EspInstance* handle);

    // ── Version ──────────────────────────────────────────────
    SSELex_API const char* C_GetVersion();
    SSELex_API int          C_GetVersionLength();

    // ── Filter ───────────────────────────────────────────────
    SSELex_API void C_InitFilter(EspInstance* handle);
    SSELex_API int  C_SetSkyrimFilter(EspInstance* handle);
    SSELex_API int  C_GetFilter(EspInstance* handle, uint8_t* buffer, int bufferSize);
    SSELex_API int  C_SetFilter(EspInstance* handle, const char* parentSig, const char** childSigs, int childCount);
    SSELex_API void C_ClearFilter(EspInstance* handle);

    // ── IO ───────────────────────────────────────────────────
    SSELex_API int          C_ReadEsp(EspInstance* handle, const wchar_t* EspPath);
    SSELex_API bool         C_SaveEsp(EspInstance* handle, const char* Utf8Path);
    SSELex_API void         C_Clear(EspInstance* handle);

    // ── Field report ─────────────────────────────────────────
    SSELex_API const char* C_GetFieldReport(EspInstance* handle);
    SSELex_API int          C_GetFieldReportLength(EspInstance* handle);

    // ── Search ───────────────────────────────────────────────
    SSELex_API EspRecord** C_SearchBySig(EspInstance* handle, const char* ParentSig, const char* ChildSig, int* OutCount);
    SSELex_API void         FreeSearchResults(EspRecord** Arr, int Count);

    // ── Record accessors (record handle not instance) ────────
    SSELex_API int          C_GetRecordSig(EspRecord* record, uint8_t* buffer, int bufferSize);
    SSELex_API uint32_t     C_GetRecordFormID(EspRecord* record);
    SSELex_API const char* C_GetRecordEditorID(EspRecord* record);
    SSELex_API uint32_t     C_GetRecordFlags(EspRecord* record);
    SSELex_API int          C_GetRecordIndex(EspRecord* record);
    SSELex_API int          C_GetSubRecordCount(EspRecord* record);

    // ── SubRecord accessors ──────────────────────────────────
    SSELex_API const SubRecordData* C_GetSubRecordData_Ptr(EspRecord* record, int index);
    SSELex_API int          C_SubRecordData_GetOccurrenceIndex(const SubRecordData* sub);
    SSELex_API int          C_SubRecordData_GetIndex(const SubRecordData* sub);
    SSELex_API const char* C_SubRecordData_GetSig(const SubRecordData* sub);
    SSELex_API const char* C_SubRecordData_GetString(const SubRecordData* sub);
    SSELex_API bool         C_SubRecordData_IsLocalized(const SubRecordData* sub);
    SSELex_API uint32_t     C_SubRecordData_GetStringID(const SubRecordData* sub);
    SSELex_API int          C_SubRecordData_GetDataSize(const SubRecordData* sub);
    SSELex_API bool         C_SubRecordData_GetData(const SubRecordData* sub, uint8_t* buffer, int bufferSize);
    SSELex_API int          C_SubRecordData_GetStringUtf8(const SubRecordData* sub, uint8_t* buffer, int bufferSize);
    SSELex_API int          C_SubRecordData_GetSigUtf8(const SubRecordData* sub, uint8_t* buffer, int bufferSize);

    // ── Modify ───────────────────────────────────────────────
    SSELex_API bool C_ModifySubRecordByOffset(EspInstance* handle, int IsCell, int RecordOffset, int SubOffset, const char* NewUtf8Data);
    SSELex_API bool C_ModifySubRecord(EspInstance* handle, uint32_t FormID, const char* RecordSig, const char* SubSig, int OccurrenceIndex, int GlobalIndex, const char* NewUtf8Data);

    // ── Character tracker ────────────────────────────────────
    SSELex_API void     C_ClearCharacterTracker(EspInstance* handle);
    SSELex_API int      C_GetCharacterCount(EspInstance* handle);
    SSELex_API uint32_t C_GetCharacterFormID(EspInstance* handle, int Index);
    SSELex_API int      C_GetCharacterName(EspInstance* handle, int Index, uint8_t* Buffer, int BufferSize);
    SSELex_API int      C_GetCharacterEditorID(EspInstance* handle, int Index, uint8_t* Buffer, int BufferSize);
    SSELex_API int      C_GetCharacterVoiceType(EspInstance* handle, int Index, uint8_t* Buffer, int BufferSize);
    SSELex_API int      C_GetCharacterGender(EspInstance* handle, int Index);
    SSELex_API int      C_GetCharacterLinkedInfoCount(EspInstance* handle, int Index);
    SSELex_API uint32_t C_GetCharacterLinkedInfo(EspInstance* handle, int Index, int LinkIndex);
    SSELex_API int      C_GetCharacterLinkedFactionCount(EspInstance* handle, int Index);
    SSELex_API uint32_t C_GetCharacterLinkedFaction(EspInstance* handle, int Index, int LinkIndex);
    SSELex_API int      C_GetCharacterLinkedRaceCount(EspInstance* handle, int Index);
    SSELex_API uint32_t C_GetCharacterLinkedRace(EspInstance* handle, int Index, int LinkIndex);
    SSELex_API int      C_GetCharacterLinkedVoiceTypeCount(EspInstance* handle, int Index);
    SSELex_API uint32_t C_GetCharacterLinkedVoiceType(EspInstance* handle, int Index, int LinkIndex);

    // ── Dialogue context (new, based on offsets) ──────────────
    SSELex_API C_LinkDIAL __stdcall C_GetDialContext(EspInstance* handle, int RecordOffset, int SubOffset);
    SSELex_API C_LinkDIAL __stdcall C_GetDialContextByDial(EspInstance* handle, int RecordOffset);
    SSELex_API void       __stdcall C_FreeDialContext(C_LinkDIAL* context);

    SSELex_API int C_GetTitleIndexByBookDesc(EspInstance* Handle, int RecordOffset, int DescSubOffset);
    SSELex_API int C_GetDescIndexByBookTitle(EspInstance* Handle, int RecordOffset, int DescSubOffset);
}

// ── Implementation ────────────────────────────────────────────

EspInstance* C_CreateInstance() { return new EspInstance(); }
void         C_DestroyInstance(EspInstance* h) { delete h; }

const char* C_GetVersion() { return Version.c_str(); }
int          C_GetVersionLength() { return static_cast<int>(Version.length()); }

void C_InitFilter(EspInstance* h)
{
    if (!h) return;
    delete h->Filter;
    h->Filter = new RecordFilter();
}

int C_GetFilter(EspInstance* h, uint8_t* buffer, int bufferSize)
{
    if (!h || !h->Filter) return -1;
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

int C_SetSkyrimFilter(EspInstance* h)
{
    if (!h || !h->Filter) return -1;
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

int C_SetFilter(EspInstance* h, const char* ParentSig, const char** ChildSigs, int ChildCount)
{
    if (!h || !h->Filter || !ParentSig) return -1;
    std::string Parent(ParentSig);
    std::vector<std::string>& Vec = h->Filter->CurrentConfig[Parent];
    for (int i = 0; i < ChildCount; ++i) Vec.push_back(std::string(ChildSigs[i]));

    h->Filter->RebuildFilters();

    return static_cast<int>(Vec.size());
}

void C_ClearFilter(EspInstance* Handle)
{
    if (Handle && Handle->Filter)
    {
        Handle->Filter->ClearFilters();
    }
}


C_LinkDIAL __stdcall C_GetDialContextByDial(EspInstance* handle, int RecordOffset)
{
    C_LinkDIAL result = {};
    if (!handle || !handle->Data) return result;

    LinkDIAL* context = handle->Data->GetDialContextByDialIndex(RecordOffset);
    if (!context) return result;

    result.HasData = 1;
    result.Head.ResponseID = context->Head.ResponseID;
    result.Head.EmotionType = context->Head.EmotionType;
    result.Head.RecordOffset = context->Head.RecordOffset;
    result.Head.SubOffset = context->Head.SubOffset;

    result.LinkCount = (uint32_t)context->Links.size();
    if (result.LinkCount > 0)
    {
        C_DialResponseNode* linkArray = new C_DialResponseNode[result.LinkCount];
        for (uint32_t i = 0; i < result.LinkCount; ++i)
        {
            linkArray[i].ResponseID = context->Links[i].ResponseID;
            linkArray[i].EmotionType = context->Links[i].EmotionType;
            linkArray[i].RecordOffset = context->Links[i].RecordOffset;
            linkArray[i].SubOffset = context->Links[i].SubOffset;
        }
        result.Links = linkArray;
    }

    delete context;
    return result;
}

// --- New dialogue context API ---

C_LinkDIAL __stdcall C_GetDialContext(EspInstance* handle, int RecordOffset, int SubOffset)
{
    C_LinkDIAL result = {};
    if (!handle || !handle->Data) return result;

    LinkDIAL* context = handle->Data->GetDialContextByIndex(RecordOffset, SubOffset);
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
        C_DialResponseNode* linkArray = new C_DialResponseNode[result.LinkCount];
        for (size_t i = 0; i < result.LinkCount; ++i)
        {
            linkArray[i].ResponseID = context->Links[i].ResponseID;
            linkArray[i].EmotionType = context->Links[i].EmotionType;
            linkArray[i].RecordOffset = context->Links[i].RecordOffset;
            linkArray[i].SubOffset = context->Links[i].SubOffset;
        }
        result.Links = linkArray;
    }

    delete context;
    return result;
}

void __stdcall C_FreeDialContext(C_LinkDIAL* context)
{
    if (!context) return;

    delete[] context->Links;
    context->Links = nullptr;
    context->LinkCount = 0;
    context->HasData = 0;
}

int C_GetTitleIndexByBookDesc(EspInstance* Handle, int RecordOffset, int DescSubOffset)
{
    if (!Handle || !Handle->Data) return -1;
    return Handle->Data->GetTitleIndexByBookDesc(RecordOffset, DescSubOffset);
}

int C_GetDescIndexByBookTitle(EspInstance* Handle, int RecordOffset, int DescSubOffset)
{
    if (!Handle || !Handle->Data) return -1;
    return Handle->Data->GetDescIndexByBookTitle(RecordOffset, DescSubOffset);
}

// --- Other C API functions (unchanged) ---

int C_ReadEsp(EspInstance* Instance, const wchar_t* EspPath)
{
    if (!Instance) return -1;

    // Reset per-read state
    delete Instance->TextValidator; Instance->TextValidator = new ESP_HeuristicAnalysis();
    delete Instance->CharTracker;   Instance->CharTracker = new CharacterTracker();
    Instance->ClearData();

    Instance->LastSetPath = EspPath;
    Instance->Data = new EspData();

    std::ifstream Stream(EspPath, std::ios::binary);
    if (!Stream.is_open()) return 1;

    while (Stream.good() && Stream.peek() != EOF)
    {
        char Sig[4];
        if (!Stream.read(Sig, 4)) break;

        if (IsGRUP(Sig)) ParseGroupIterative_Inst(Instance, Stream);
        else ParseRecord_Inst(Instance, Stream, Sig, 0);
    }

    FlushDeferredInfoLinks_Inst(Instance);
    Instance->CharacterCacheDirty = true;

    Instance->Data->BuildDialTopologyIndex();

    return 0;
}

bool C_SaveEsp(EspInstance* h, const char* Utf8Path)
{
    return SaveEsp_Inst(h, Utf8Path);
}

void C_Clear(EspInstance* h) { if (h) h->ClearData(); }

const char* C_GetFieldReport(EspInstance* h)
{
    if (!h || !h->TextValidator) { static const char* e = "Validator not initialized"; return e; }
    static std::string buf; buf = h->TextValidator->ExportFieldReport(); return buf.c_str();
}
int C_GetFieldReportLength(EspInstance* h)
{
    if (!h || !h->TextValidator) return 0;
    static std::string buf; buf = h->TextValidator->ExportFieldReport(); return static_cast<int>(buf.length());
}

EspRecord** C_SearchBySig(EspInstance* h, const char* ParentSig, const char* ChildSig, int* OutCount)
{
    *OutCount = 0;
    if (!h || !h->Data) return nullptr;
    std::vector<EspRecord> Matches = h->Data->SearchBySig(ParentSig, ChildSig ? ChildSig : "");
    *OutCount = static_cast<int>(Matches.size());
    if (Matches.empty()) return nullptr;
    EspRecord** Result = new EspRecord * [*OutCount];
    for (int i = 0; i < *OutCount; ++i) Result[i] = new EspRecord(Matches[i]);
    return Result;
}

void FreeSearchResults(EspRecord** Arr, int Count)
{
    if (!Arr) return;
    for (int i = 0; i < Count; ++i) delete Arr[i];
    delete[] Arr;
}

// Record accessors (unchanged)
const SubRecordData* C_GetSubRecordData_Ptr(EspRecord* r, int i)
{
    if (!r || i < 0 || i >= (int)r->SubRecords.size()) return nullptr; return &r->SubRecords[i];
}
int C_GetRecordSig(EspRecord* r, uint8_t* b, int bs)
{
    if (!r) return -1; int l = (int)r->Sig.size();
    if (b && bs > l) { std::memcpy(b, r->Sig.c_str(), l); b[l] = 0; } return l;
}
uint32_t    C_GetRecordFormID(EspRecord* r) { return r ? r->FormID : 0; }
const char* C_GetRecordEditorID(EspRecord* r) { if (!r) return nullptr; static std::string buf; buf = r->EditorID; return buf.c_str(); }
uint32_t    C_GetRecordFlags(EspRecord* r) { return r ? r->Flags : 0; }
int         C_GetRecordIndex(EspRecord* r) { return r ? r->Index : 0; }
int         C_GetSubRecordCount(EspRecord* r) { return r ? (int)r->SubRecords.size() : 0; }

int         C_SubRecordData_GetOccurrenceIndex(const SubRecordData* s) { return s ? s->OccurrenceIndex : -1; }
int         C_SubRecordData_GetIndex(const SubRecordData* s) { return s ? s->Index : -1; }
const char* C_SubRecordData_GetSig(const SubRecordData* s) { return s ? s->Sig.c_str() : nullptr; }
const char* C_SubRecordData_GetString(const SubRecordData* s) { if (!s) return nullptr; static std::string buf; buf = s->GetString(); return buf.c_str(); }
bool        C_SubRecordData_IsLocalized(const SubRecordData* s) { return s ? s->IsLocalized : false; }
uint32_t    C_SubRecordData_GetStringID(const SubRecordData* s) { return s ? s->StringID : 0; }
int         C_SubRecordData_GetDataSize(const SubRecordData* s) { return s ? (int)s->Data.size() : 0; }
bool        C_SubRecordData_GetData(const SubRecordData* s, uint8_t* b, int bs)
{
    if (!s || !b) return false; if (bs < (int)s->Data.size()) return false;
    std::memcpy(b, s->Data.data(), s->Data.size()); return true;
}
int C_SubRecordData_GetStringUtf8(const SubRecordData* s, uint8_t* b, int bs)
{
    if (!s) return -1; std::string str = s->GetString(); int l = (int)strlen(str.c_str());
    if (b && bs > l) std::memcpy(b, str.c_str(), l + 1); return l;
}
int C_SubRecordData_GetSigUtf8(const SubRecordData* s, uint8_t* b, int bs)
{
    if (!s) return -1; int l = (int)s->Sig.size();
    if (b && bs > l) { std::memcpy(b, s->Sig.c_str(), l); b[l] = 0; } return l;
}

// Modify
bool C_ModifySubRecordByOffset(EspInstance* h, int IsCell, int RecordOffset, int SubOffset, const char* NewUtf8Data)
{
    if (!h || !h->Data) return false;
    std::vector<EspRecord>& Records = (IsCell == 1) ? h->Data->CellRecords : h->Data->Records;
    if (RecordOffset < 0 || RecordOffset >= (int)Records.size()) return false;
    EspRecord& Rec = Records[RecordOffset];
    if (SubOffset < 0 || SubOffset >= (int)Rec.SubRecords.size()) return false;
    SubRecordData& Sub = Rec.SubRecords[SubOffset];
    if (NewUtf8Data)
    {
        int len = (int)std::strlen(NewUtf8Data);
        Sub.Data.resize(len + 1);
        std::memcpy(Sub.Data.data(), NewUtf8Data, len);
        Sub.Data[len] = '\0';
        Sub.IsModify = true;
    }
    Sub.StringID = 0; Sub.IsLocalized = false;
    return true;
}

bool C_ModifySubRecord(EspInstance* h, uint32_t FormID, const char* RecordSig, const char* SubSig,
    int OccurrenceIndex, int Index, const char* NewUtf8Data)
{
    if (!h || !h->Data) return false;
    std::string strRec = RecordSig ? RecordSig : "";
    std::string strSub = SubSig ? SubSig : "";
    auto modify = [&](std::vector<EspRecord>& recs) -> bool {
        for (auto& Rec : recs)
            if (Rec.FormID == FormID && Rec.Sig == strRec)
                for (auto& Sub : Rec.SubRecords)
                    if (Sub.Sig == strSub && Sub.OccurrenceIndex == OccurrenceIndex && Sub.Index == Index)
                    {
                        if (NewUtf8Data) {
                            int len = (int)std::strlen(NewUtf8Data);
                            Sub.Data.resize(len + 1);
                            std::memcpy(Sub.Data.data(), NewUtf8Data, len);
                            Sub.Data[len] = '\0';
                            Sub.IsModify = true;
                        }
                        Sub.StringID = 0; Sub.IsLocalized = false;
                        return true;
                    }
        return false;
        };
    return modify(h->Data->Records) || modify(h->Data->CellRecords);
}

// Character tracker
void C_ClearCharacterTracker(EspInstance* h)
{
    if (!h) return;
    if (h->CharTracker) h->CharTracker->ClearAll();
    h->CharacterIndexCache.clear();
    h->CharacterCacheDirty = true;
}
int      C_GetCharacterCount(EspInstance* h) { EnsureCharacterCache(h); return (int)h->CharacterIndexCache.size(); }
uint32_t C_GetCharacterFormID(EspInstance* h, int i) { const CharacterRecord* r = GetCharacterAt(h, i); return r ? r->NpcFormID : 0; }
int      C_GetCharacterName(EspInstance* h, int i, uint8_t* b, int bs) { const CharacterRecord* r = GetCharacterAt(h, i); if (!r) return -1; return WriteStringToBuffer(r->Name, b, bs); }
int      C_GetCharacterEditorID(EspInstance* h, int i, uint8_t* b, int bs) { const CharacterRecord* r = GetCharacterAt(h, i); if (!r) return -1; return WriteStringToBuffer(r->EditorID, b, bs); }
int      C_GetCharacterVoiceType(EspInstance* h, int i, uint8_t* b, int bs) { const CharacterRecord* r = GetCharacterAt(h, i); if (!r) return -1; return WriteStringToBuffer(r->VoiceType, b, bs); }
int      C_GetCharacterGender(EspInstance* h, int i) {
    const CharacterRecord* r = GetCharacterAt(h, i); if (!r) return 0;
    switch (r->Gender) { case CharacterGender::Male: return 1; case CharacterGender::Female: return 2; default: return 0; }
}
int      C_GetCharacterLinkedInfoCount(EspInstance* h, int i) { const CharacterRecord* r = GetCharacterAt(h, i); return r ? (int)r->LinkedInfos.size() : 0; }
uint32_t C_GetCharacterLinkedInfo(EspInstance* h, int i, int li) { const CharacterRecord* r = GetCharacterAt(h, i); if (!r || li < 0 || li >= (int)r->LinkedInfos.size()) return 0; return r->LinkedInfos[li]; }
int      C_GetCharacterLinkedFactionCount(EspInstance* h, int i) { const CharacterRecord* r = GetCharacterAt(h, i); return r ? (int)r->LinkedFactions.size() : 0; }
uint32_t C_GetCharacterLinkedFaction(EspInstance* h, int i, int li) { const CharacterRecord* r = GetCharacterAt(h, i); if (!r || li < 0 || li >= (int)r->LinkedFactions.size()) return 0; return r->LinkedFactions[li]; }
int      C_GetCharacterLinkedRaceCount(EspInstance* h, int i) { const CharacterRecord* r = GetCharacterAt(h, i); return r ? (int)r->LinkedRaces.size() : 0; }
uint32_t C_GetCharacterLinkedRace(EspInstance* h, int i, int li) { const CharacterRecord* r = GetCharacterAt(h, i); if (!r || li < 0 || li >= (int)r->LinkedRaces.size()) return 0; return r->LinkedRaces[li]; }
int      C_GetCharacterLinkedVoiceTypeCount(EspInstance* h, int i) { const CharacterRecord* r = GetCharacterAt(h, i); return r ? (int)r->LinkedVoiceTypes.size() : 0; }
uint32_t C_GetCharacterLinkedVoiceType(EspInstance* h, int i, int li) { const CharacterRecord* r = GetCharacterAt(h, i); if (!r || li < 0 || li >= (int)r->LinkedVoiceTypes.size()) return 0; return r->LinkedVoiceTypes[li]; }

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

    bool result = SaveEsp_Inst(instance, utf8Path.c_str());
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