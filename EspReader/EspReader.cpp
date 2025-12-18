#include <fstream>
#include <vector>
#include <string>
#include <iostream>
#include <cstdint>
#include <stack>
#include <unordered_map>
#include <unordered_set>
#include "miniz.h"
#include "EspRecord.h"

#pragma pack(push, 1)
struct RecordHeader {
    char     sig[4];
    uint32_t dataSize;
    uint32_t flags;
    uint32_t formID;
    uint32_t versionCtrl;
    uint16_t version;
    uint16_t unknown;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct GroupHeader {
    char     sig[4];   // "GRUP"
    uint32_t size;
    char     label[4];
    uint32_t groupType;
    uint32_t stamp;
    uint32_t unknown;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct SubRecordHeader {
    char sig[4];
    uint16_t size;
};
#pragma pack(pop)

constexpr uint32_t RECORD_FLAG_COMPRESSED = 0x00040000;

// ===== Record Filter Configuration =====
class RecordFilter {
public:
    void AddRecordType(const std::string& recordType, const std::vector<std::string>& subRecords) {
        std::string sig = recordType.substr(0, 4); 
        recordTypes_.insert(sig);

        for (size_t i = 0; i < subRecords.size(); ++i) {
            std::string subSig = subRecords[i].substr(0, 4);
            subRecordFilters_[sig].insert(subSig);
        }
    }

    bool ShouldParseRecord(const char sig[4]) const {
        if (recordTypes_.empty()) return true;
        
        for (std::unordered_set<std::string>::const_iterator it = recordTypes_.begin();
            it != recordTypes_.end(); ++it) {
            if (std::strncmp(it->c_str(), sig, 4) == 0) return true;
        }
        return false;
    }

    bool ShouldParseSubRecord(const char recordSig[4], const char subSig[4]) const {
        for (std::unordered_map<std::string, std::unordered_set<std::string>>::const_iterator it = subRecordFilters_.begin();
            it != subRecordFilters_.end(); ++it) {
            if (std::strncmp(it->first.c_str(), recordSig, 4) != 0) continue;

            const std::unordered_set<std::string>& subs = it->second;
            for (std::unordered_set<std::string>::const_iterator sit = subs.begin();
                sit != subs.end(); ++sit) {
                if (std::strncmp(sit->c_str(), subSig, 4) == 0) return true;
            }
            return false;
        }

        return true; 
    }

  
    void LoadFromConfig(const std::unordered_map<std::string, std::vector<std::string>>& config) 
    {

        for (std::unordered_map<std::string, std::vector<std::string>>::const_iterator it = config.begin();
            it != config.end(); ++it) {
            AddRecordType(it->first, it->second);
        }
    }

    bool IsEnabled() const {
        return !recordTypes_.empty();
    }

private:
    std::unordered_set<std::string> recordTypes_;
    std::unordered_map<std::string, std::unordered_set<std::string>> subRecordFilters_;
};

// Read helper
template<typename T>
inline void Read(std::ifstream& f, T& out) { f.read(reinterpret_cast<char*>(&out), sizeof(T)); }
inline bool IsGRUP(const char sig[4]) { return std::memcmp(sig, "GRUP", 4) == 0; }
bool IsCompressed(const RecordHeader& hdr) { return (hdr.flags & RECORD_FLAG_COMPRESSED) != 0; }

// Decompress
bool ZlibDecompress(const uint8_t* src, size_t srcSize, std::vector<uint8_t>& out, size_t uncompressedSize)
{
    out.resize(uncompressedSize);
    size_t ret = tinfl_decompress_mem_to_mem(out.data(), uncompressedSize, src, srcSize, TINFL_FLAG_PARSE_ZLIB_HEADER);
    return ret == uncompressedSize;
}

// Parse subrecords from memory buffer with filter
void ParseSubRecords(const uint8_t* data, size_t dataSize, EspRecord& rec,
    const RecordFilter& filter, const char recordSig[4])
{
    size_t offset = 0;
    while (offset + sizeof(SubRecordHeader) <= dataSize) {
        const SubRecordHeader* sub = reinterpret_cast<const SubRecordHeader*>(data + offset);
        if (offset + sizeof(SubRecordHeader) + sub->size > dataSize) break;

        if (filter.ShouldParseSubRecord(recordSig, sub->sig)) {
            rec.AddSubRecord(sub->sig, data + offset + sizeof(SubRecordHeader), sub->size);
        }

        offset += sizeof(SubRecordHeader) + sub->size;
    }
}

// Parse subrecords from stream with filter
void ParseSubRecordsStream(std::ifstream& f, uint32_t recordSize, EspRecord& rec,
    const RecordFilter& filter, const char recordSig[4])
{
    uint32_t bytesRead = 0;
    while (bytesRead < recordSize && f.good()) {
        if (bytesRead + sizeof(SubRecordHeader) > recordSize) {
            f.seekg(recordSize - bytesRead, std::ios::cur);
            break;
        }

        SubRecordHeader sub{};
        if (!f.read(reinterpret_cast<char*>(&sub), sizeof(sub))) break;
        bytesRead += sizeof(SubRecordHeader);

        if (bytesRead + sub.size > recordSize) {
            f.seekg(recordSize - bytesRead, std::ios::cur);
            break;
        }

        std::vector<uint8_t> buf(sub.size);
        if (sub.size > 0) {
            f.read(reinterpret_cast<char*>(buf.data()), sub.size);
            bytesRead += sub.size;
        }

        if (filter.ShouldParseSubRecord(recordSig, sub.sig)) {
            rec.AddSubRecord(sub.sig, buf.data(), sub.size);
        }
    }
}

void ParseRecord(std::ifstream& f, const char sig[4], EspDocument& doc, const RecordFilter& filter)
{
    RecordHeader hdr{};
    std::memcpy(hdr.sig, sig, 4);
    Read(f, hdr.dataSize);
    Read(f, hdr.flags);
    Read(f, hdr.formID);
    Read(f, hdr.versionCtrl);
    Read(f, hdr.version);
    Read(f, hdr.unknown);

    if (!filter.ShouldParseRecord(hdr.sig)) 
    {
        f.seekg(hdr.dataSize, std::ios::cur);
        return;
    }

    EspRecord rec(hdr.sig, hdr.formID, hdr.flags);

    if (IsCompressed(hdr)) {
        if (hdr.dataSize < 4) {
            f.seekg(hdr.dataSize, std::ios::cur);
            doc.AddRecord(std::move(rec));
            return;
        }

        uint32_t uncompressedSize = 0;
        Read(f, uncompressedSize);

        uint32_t compressedSize = hdr.dataSize - 4;
        std::vector<uint8_t> compressed(compressedSize);
        f.read(reinterpret_cast<char*>(compressed.data()), compressedSize);

        std::vector<uint8_t> decompressed;
        if (ZlibDecompress(compressed.data(), compressedSize, decompressed, uncompressedSize))
            ParseSubRecords(decompressed.data(), decompressed.size(), rec, filter, hdr.sig);
    }
    else {
        ParseSubRecordsStream(f, hdr.dataSize, rec, filter, hdr.sig);
    }

    doc.AddRecord(std::move(rec));
}

// Iterative group parsing with filter
void ParseGroupIterative(std::ifstream& f, EspDocument &doc, const RecordFilter& filter)
{
    struct GroupState {
        uint32_t remaining;
    };
    std::stack<GroupState> groupStack;

    // Read rest of GRUP header (sig already read)
    GroupHeader gh{};
    std::memcpy(gh.sig, "GRUP", 4);
    Read(f, gh.size);
    f.read(gh.label, 4);
    Read(f, gh.groupType);
    Read(f, gh.stamp);
    Read(f, gh.unknown);

    if (gh.size < 24) return;

    // Count this GRUP
    doc.IncrementGrupCount();

    groupStack.push({ gh.size - 24 });

    while (!groupStack.empty()) {
        auto& state = groupStack.top();

        if (state.remaining == 0) {
            groupStack.pop();
            continue;
        }

        if (state.remaining < 4) {
            f.seekg(state.remaining, std::ios::cur);
            groupStack.pop();
            continue;
        }

        char sig[4];
        if (!f.read(sig, 4)) {
            groupStack.pop();
            continue;
        }

        if (IsGRUP(sig)) {
            if (state.remaining < 24) {
                f.seekg(state.remaining - 4, std::ios::cur);
                groupStack.pop();
                continue;
            }

            // Read rest of nested GRUP header
            Read(f, gh.size);
            f.read(gh.label, 4);
            Read(f, gh.groupType);
            Read(f, gh.stamp);
            Read(f, gh.unknown);

            if (gh.size < 24 || gh.size > state.remaining) {
                groupStack.pop();
                continue;
            }

            // Count this nested GRUP
            doc.IncrementGrupCount();

            state.remaining -= gh.size;
            groupStack.push({ gh.size - 24 });
        }
        else {
            if (state.remaining < 24) {
                f.seekg(state.remaining - 4, std::ios::cur);
                groupStack.pop();
                continue;
            }

            // Parse record header to get size
            RecordHeader hdr{};
            std::memcpy(hdr.sig, sig, 4);
            Read(f, hdr.dataSize);
            Read(f, hdr.flags);
            Read(f, hdr.formID);
            Read(f, hdr.versionCtrl);
            Read(f, hdr.version);
            Read(f, hdr.unknown);

            uint32_t recordTotalSize = 24 + hdr.dataSize;

            if (recordTotalSize > state.remaining) {
                groupStack.pop();
                continue;
            }

            if (!filter.ShouldParseRecord(hdr.sig)) 
            {
                f.seekg(hdr.dataSize, std::ios::cur);
                state.remaining -= recordTotalSize;
                continue;
            }

            // Now parse the record data
            EspRecord rec(hdr.sig, hdr.formID, hdr.flags);

            if (IsCompressed(hdr)) {
                if (hdr.dataSize < 4) {
                    f.seekg(hdr.dataSize, std::ios::cur);
                }
                else {
                    uint32_t uncompressedSize = 0;
                    Read(f, uncompressedSize);

                    uint32_t compressedSize = hdr.dataSize - 4;
                    std::vector<uint8_t> compressed(compressedSize);
                    f.read(reinterpret_cast<char*>(compressed.data()), compressedSize);

                    std::vector<uint8_t> decompressed;
                    if (ZlibDecompress(compressed.data(), compressedSize, decompressed, uncompressedSize))
                        ParseSubRecords(decompressed.data(), decompressed.size(), rec, filter, hdr.sig);
                }
            }
            else {
                ParseSubRecordsStream(f, hdr.dataSize, rec, filter, hdr.sig);
            }

            doc.AddRecord(std::move(rec));
            state.remaining -= recordTotalSize;
        }
    }
}

EspDocument* CurrentDocument;

// Read ESP with filter
int ReadEsp(const char* EspPath, const RecordFilter& filter)
{
    CurrentDocument = new EspDocument();

    std::ifstream f(EspPath, std::ios::binary);
    if (!f.is_open()) {
        std::cerr << "Failed to open ESP: " << EspPath << "\n";
        return 1;
    }

    while (f.good() && f.peek() != EOF) {
        char sig[4];
        if (!f.read(sig, 4)) break;

        if (IsGRUP(sig)) {
            ParseGroupIterative(f, *CurrentDocument, filter);
        }
        else {
            ParseRecord(f, sig, *CurrentDocument, filter);
        }
    }
    return 0;
}

RecordFilter* TranslateFilter;
void Init()
{
    TranslateFilter = new RecordFilter();

    // https://github.com/Cutleast/sse-plugin-interface/blob/master/src/sse_plugin_interface/string_records.py#L6-L47 
    //It borrows from the fields available for translation in sseat.
    std::unordered_map<std::string, std::vector<std::string>> Config = {
       {"ACTI", {"FULL", "RNAM"}},
       {"ALCH", {"FULL"}},
       {"AMMO", {"FULL", "DESC"}},
       {"APPA", {"FULL", "DESC"}},
       {"ARMO", {"FULL", "DESC"}},
       {"AVIF", {"FULL", "DESC"}},
       {"BOOK", {"FULL", "DESC", "CNAM"}},
       {"CLAS", {"FULL"}},
       {"CELL", {"FULL"}},
       {"CONT", {"FULL"}},
       {"DIAL", {"FULL"}},
       {"DOOR", {"FULL"}},
       {"ENCH", {"FULL"}},
       {"EXPL", {"FULL"}},
       {"FLOR", {"FULL", "RNAM"}},
       {"FURN", {"FULL"}},
       {"HAZD", {"FULL"}},
       {"INFO", {"NAM1", "RNAM"}},
       {"INGR", {"FULL"}},
       {"KEYM", {"FULL"}},
       {"LCTN", {"FULL"}},
       {"LIGH", {"FULL"}},
       {"LSCR", {"DESC"}},
       {"MESG", {"DESC", "FULL", "ITXT"}},
       {"MGEF", {"FULL", "DNAM"}},
       {"MISC", {"FULL"}},
       {"NPC_", {"FULL", "SHRT"}},
       {"NOTE", {"FULL", "TNAM"}},
       {"PERK", {"FULL", "DESC", "EPF2", "EPFD"}},
       {"PROJ", {"FULL"}},
       {"QUST", {"FULL", "CNAM", "NNAM"}},
       {"RACE", {"FULL", "DESC"}},
       {"REFR", {"FULL"}},
       {"REGN", {"RDMP"}},
       {"SCRL", {"FULL", "DESC"}},
       {"SHOU", {"FULL", "DESC"}},
       {"SLGM", {"FULL"}},
       {"SPEL", {"FULL", "DESC"}},
       {"TACT", {"FULL"}},
       {"TREE", {"FULL"}},
       {"WEAP", {"DESC", "FULL"}},
       {"WOOP", {"FULL", "TNAM"}},
       {"WRLD", {"FULL"}},
    };

    TranslateFilter->LoadFromConfig(Config);
}

int main()
{
    Init();

    const char* EspPath = "C:\\Users\\52508\\Desktop\\1TestMod\\Skyrim.esm";

    std::cout << "Starting ESP parsing with filter...\n";
    if (TranslateFilter->IsEnabled()) {
        std::cout << "Filter is enabled - only specified records will be parsed.\n";
    }
    else {
        std::cout << "Filter is disabled - all records will be parsed.\n";
    }

    int state = ReadEsp(EspPath,*TranslateFilter);

    if (state == 0) {
        std::cout << "Finished reading ESP.\n";
        std::cout << "Total records parsed: " << CurrentDocument->GetTotalCount() << "\n";

        // Print statistics
        CurrentDocument->PrintStatistics();
    }
    else {
        std::cerr << "Failed to read ESP\n";
    }

    return 0;
}

std::vector<const EspRecord*> FindCellsByEditorID(char* EditorID)
{
    auto CellRecs = CurrentDocument->FindCellsByEditorID("WhiterunWorld");
    if (!CellRecs.empty()) {
        std::cout << "\nFound " << CellRecs.size()
            << " CELL records with EDID 'WhiterunWorld'\n";
    }

    return CellRecs;
}