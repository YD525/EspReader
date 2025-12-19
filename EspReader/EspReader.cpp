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
#include <random>

#define NOMINMAX  
#define WIN32_LEAN_AND_MEAN 

#include <windows.h>

void Close();
void ClearDocument();

#pragma pack(push, 1)
struct RecordHeader 
{
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
struct GroupHeader 
{
    char     sig[4];   // "GRUP"
    uint32_t size;
    char     label[4];
    uint32_t groupType;
    uint32_t stamp;
    uint32_t unknown;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct SubRecordHeader 
{
    char sig[4];
    uint16_t size;
};
#pragma pack(pop)

constexpr uint32_t RECORD_FLAG_COMPRESSED = 0x00040000;

// ===== Record Filter Configuration =====
class RecordFilter 
{
    public:
    void AddRecordType(const std::string& recordType, const std::vector<std::string>& subRecords) 
    {
        std::string sig = recordType.substr(0, 4);
        recordTypes_.insert(sig);

        for (size_t i = 0; i < subRecords.size(); ++i) 
        {
            std::string subSig = subRecords[i].substr(0, 4);
            subRecordFilters_[sig].insert(subSig);
        }
    }

    bool ShouldParseRecord(const char sig[4]) const 
    {
        return recordTypes_.count(std::string(sig, 4)) > 0;
    }

    bool ShouldParseSubRecord(const char recordSig[4], const char subSig[4]) const 
    {
        auto it = subRecordFilters_.find(std::string(recordSig, 4));
        if (it == subRecordFilters_.end()) return false; 

        const std::unordered_set<std::string>& subs = it->second;
        if (subs.empty()) return true; 

        for (const auto& s : subs) 
        {
            if (std::strncmp(s.c_str(), subSig, 4) == 0) return true;
        }

        return false; 
    }

    std::unordered_map<std::string, std::vector<std::string>> CurrentConfig;
    void LoadFromConfig(const std::unordered_map<std::string, std::vector<std::string>>& config)
    {
        CurrentConfig = config;
        for (std::unordered_map<std::string, std::vector<std::string>>::const_iterator it = config.begin();
            it != config.end(); ++it) 
        {
            AddRecordType(it->first, it->second);
        }
    }

    bool IsEnabled() const 
    {
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

//EnCompress
bool ZlibCompress(const uint8_t* src, size_t srcSize, std::vector<uint8_t>& out)
{
    mz_ulong destLen = compressBound(srcSize);
    out.resize(destLen);
    int ret = compress2(out.data(), &destLen, src, srcSize, Z_BEST_COMPRESSION);
    if (ret != Z_OK) return false;
    out.resize(destLen);
    return true;
}

// Parse subrecords from memory buffer with filter
void ParseSubRecords(const uint8_t* data, size_t dataSize, EspRecord& rec,
    const RecordFilter& filter, const char recordSig[4])
{
    size_t offset = 0;
    while (offset + sizeof(SubRecordHeader) <= dataSize) 
    {
        const SubRecordHeader* sub = reinterpret_cast<const SubRecordHeader*>(data + offset);
        if (offset + sizeof(SubRecordHeader) + sub->size > dataSize) break;

        if (filter.ShouldParseSubRecord(recordSig, sub->sig)) 
        {
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
    while (bytesRead < recordSize && f.good()) 
    {
        if (bytesRead + sizeof(SubRecordHeader) > recordSize) 
        {
            f.seekg(recordSize - bytesRead, std::ios::cur);
            break;
        }

        SubRecordHeader sub{};
        if (!f.read(reinterpret_cast<char*>(&sub), sizeof(sub))) break;
        bytesRead += sizeof(SubRecordHeader);

        if (bytesRead + sub.size > recordSize) 
        {
            f.seekg(recordSize - bytesRead, std::ios::cur);
            break;
        }

        std::vector<uint8_t> buf(sub.size);
        if (sub.size > 0) 
        {
            f.read(reinterpret_cast<char*>(buf.data()), sub.size);
            bytesRead += sub.size;
        }

        if (filter.ShouldParseSubRecord(recordSig, sub.sig)) 
        {
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

    if (IsCompressed(hdr)) 
    {
        if (hdr.dataSize < 4) 
        {
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
        {
            ParseSubRecords(decompressed.data(), decompressed.size(), rec, filter, hdr.sig);
        }  
    }
    else 
    {
        ParseSubRecordsStream(f, hdr.dataSize, rec, filter, hdr.sig);
    }

    doc.AddRecord(std::move(rec));
}

// Iterative group parsing with filter
void ParseGroupIterative(std::ifstream& f, EspDocument& doc, const RecordFilter& filter)
{
    struct GroupState 
    {
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

        if (state.remaining == 0) 
        {
            groupStack.pop();
            continue;
        }

        if (state.remaining < 4) 
        {
            f.seekg(state.remaining, std::ios::cur);
            groupStack.pop();
            continue;
        }

        char sig[4];
        if (!f.read(sig, 4)) 
        {
            groupStack.pop();
            continue;
        }

        if (IsGRUP(sig)) 
        {
            if (state.remaining < 24) 
            {
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

            if (gh.size < 24 || gh.size > state.remaining) 
            {
                groupStack.pop();
                continue;
            }

            // Count this nested GRUP
            doc.IncrementGrupCount();

            state.remaining -= gh.size;
            groupStack.push({ gh.size - 24 });
        }
        else 
        {
            if (state.remaining < 24) 
            {
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

            if (recordTotalSize > state.remaining) 
            {
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

            if (IsCompressed(hdr)) 
            {
                if (hdr.dataSize < 4) 
                {
                    f.seekg(hdr.dataSize, std::ios::cur);
                }
                else 
                {
                    uint32_t uncompressedSize = 0;
                    Read(f, uncompressedSize);

                    uint32_t compressedSize = hdr.dataSize - 4;
                    std::vector<uint8_t> compressed(compressedSize);
                    f.read(reinterpret_cast<char*>(compressed.data()), compressedSize);

                    std::vector<uint8_t> decompressed;
                    if (ZlibDecompress(compressed.data(), compressedSize, decompressed, uncompressedSize))
                    {
                        ParseSubRecords(decompressed.data(), decompressed.size(), rec, filter, hdr.sig);
                    }  
                }
            }
            else 
            {
                ParseSubRecordsStream(f, hdr.dataSize, rec, filter, hdr.sig);
            }

            doc.AddRecord(std::move(rec));
            state.remaining -= recordTotalSize;
        }
    }
}

std::string LastSetPath;
EspDocument* CurrentDocument;

// Read ESP with filter
int ReadEsp(const char* EspPath, const RecordFilter& filter)
{
    ClearDocument();//Ensure that nothing goes wrong~
    LastSetPath = EspPath;
    CurrentDocument = new EspDocument();

    std::ifstream f(EspPath, std::ios::binary);
    if (!f.is_open()) 
    {
        std::cerr << "Failed to open ESP: " << EspPath << "\n";
        return 1;
    }

    while (f.good() && f.peek() != EOF) 
    {
        char sig[4];
        if (!f.read(sig, 4)) break;

        if (IsGRUP(sig)) 
        {
            ParseGroupIterative(f, *CurrentDocument, filter);
        }
        else 
        {
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
    std::unordered_map<std::string, std::vector<std::string>> Config = 
    {
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

void WaitForExit()
{
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
}

void PrintAllRecords()
{
    if (!CurrentDocument) return;

    size_t total = CurrentDocument->records.size();
    if (total == 0) 
    {
        std::cout << "No records available.\n";
        return;
    }

    std::cout << "\n=== All Records ===\n";

    size_t index = 1;
    for (const auto& rec : CurrentDocument->records) 
    {
        std::cout << "Record " << index++ << ":\n";
        std::cout << "  Sig: " << rec.sig << "\n";
        std::cout << "  FormID: 0x" << std::hex << rec.formID << std::dec << "\n";
        std::cout << "  Key: " << rec.GetUniqueKey() << "\n";

        auto names = rec.GetSubRecordValues(TranslateFilter->CurrentConfig);
        if (!names.empty()) {
            std::cout << "  SubRecord Values: ";
            for (size_t i = 0; i < names.size(); ++i) {
                if (i > 0) std::cout << " | ";
                std::cout << names[i].first << "=" << names[i].second;
            }
            std::cout << "\n";
        }

        std::cout << "  Total SubRecords: " << rec.subRecords.size() << "\n\n";
    }
}

int main()
{
    SetConsoleOutputCP(CP_UTF8);

    Init();

    const char* EspPath = "C:\\Users\\52508\\Desktop\\1TestMod\\Interesting NPCs - 4.5 to 4.54 Update-29194-4-54-1681353795\\Data\\3DNPC.esp";

    std::cout << "Starting ESP parsing with filter...\n";
    if (TranslateFilter->IsEnabled()) 
    {
        std::cout << "Filter is enabled - only specified records will be parsed.\n";
    }
    else {
        std::cout << "Filter is disabled - all records will be parsed.\n";
    }

    int state = ReadEsp(EspPath, *TranslateFilter);

    if (state == 0) 
    {
        std::cout << "Finished reading ESP.\n";
        std::cout << "Total records parsed: " << CurrentDocument->GetTotalCount() << "\n";

        // Print statistics
        CurrentDocument->PrintStatistics();

        std::cout << "Print All Records.\n";
        PrintAllRecords();
    }
    else 
    {
        std::cerr << "Failed to read ESP\n";
    }

    Close();

    WaitForExit();

    return 0;
}

const EspRecord* GetRecord(char* Key)
{
    if (!Key)
        return {};

    std::string UniqueKey(Key);

    auto Item = CurrentDocument->FindByUniqueKey(UniqueKey);

    return Item;
}

void Close()
{
    delete TranslateFilter;
    TranslateFilter = nullptr;

    ClearDocument();
}

void ClearDocument()
{
    delete CurrentDocument;
    CurrentDocument = nullptr;

    LastSetPath = "";
}

#pragma region  SaveFunc
std::vector<uint8_t> ModifySubRecords(
    const std::vector<uint8_t>& originalData,
    EspRecord* modifiedRecord)
{
    std::vector<uint8_t> result;
    size_t offset = 0;

    // Build an index of modified subrecords: signature -> list of SubRecordData pointers
    // This allows us to handle multiple subrecords with the same signature
    std::unordered_map<std::string, std::vector<const SubRecordData*>> modifiedSubsMap;

    for (const auto& sub : modifiedRecord->subRecords)
    {
        modifiedSubsMap[sub.sig].push_back(&sub);
    }

    // Track how many times we've encountered each subrecord signature
    // This ensures we match the Nth occurrence in original data with the Nth modified version
    std::unordered_map<std::string, size_t> currentOccurrence;

    // Iterate through all subrecords in the original data
    while (offset + sizeof(SubRecordHeader) <= originalData.size())
    {
        SubRecordHeader sh;
        std::memcpy(&sh, originalData.data() + offset, sizeof(sh));

        // Validate that the subrecord doesn't exceed the data bounds
        if (offset + sizeof(SubRecordHeader) + sh.size > originalData.size())
        {
            std::cerr << "Warning: Corrupted subrecord data detected, stopping at offset "
                << offset << "\n";
            break;
        }

        std::string subSig(sh.sig, 4);

        // Check if this subrecord signature was modified
        bool isModified = false;
        const SubRecordData* modifiedSub = nullptr;

        auto mapIt = modifiedSubsMap.find(subSig);
        if (mapIt != modifiedSubsMap.end())
        {
            // Get the occurrence index for this signature
            size_t occurrence = currentOccurrence[subSig]++;

            // If we have a modified version for this occurrence, use it
            if (occurrence < mapIt->second.size())
            {
                modifiedSub = mapIt->second[occurrence];
                isModified = true;
            }
        }

        if (isModified && modifiedSub)
        {
            if (modifiedSub->data.size() > 0xFFFF)
            {
                std::cerr << "Error: Subrecord " << subSig
                    << " size exceeds 65535 bytes\n";
                return {};
            }

            // Write the modified subrecord with new data (translation)
            SubRecordHeader newSh = sh;

            newSh.size = static_cast<uint16_t>(modifiedSub->data.size());

            // Write the subrecord header
            result.insert(result.end(),
                reinterpret_cast<uint8_t*>(&newSh),
                reinterpret_cast<uint8_t*>(&newSh) + sizeof(newSh));

            // Write the modified data (UTF-8 translation)
            result.insert(result.end(),
                modifiedSub->data.begin(),
                modifiedSub->data.end());
        }
        else
        {
            // Preserve the original subrecord exactly as-is
            // This includes subrecords that weren't filtered or weren't modified
            result.insert(result.end(),
                originalData.begin() + offset,
                originalData.begin() + offset + sizeof(SubRecordHeader) + sh.size);
        }

        // Move to the next subrecord
        offset += sizeof(SubRecordHeader) + sh.size;
    }

    return result;
}

// Forward declarations
bool ProcessFileContent(std::ifstream& fin, std::ofstream& fout, int64_t remainingSize);
bool ProcessGRUP(std::ifstream& fin, std::ofstream& fout, const char sig[4]);
bool ProcessGRUPContent(std::ifstream& fin, std::ofstream& fout, int64_t contentSize);
bool ProcessRecord(std::ifstream& fin, std::ofstream& fout, const char sig[4]);

/**
 * Process file content recursively
 *
 * FIXED: Properly track bytes processed by reading stream position changes
 *
 * @param fin Input file stream
 * @param fout Output file stream
 * @param remainingSize Bytes remaining in current GRUP (-1 for top level)
 * @return true if processing succeeded
 */
bool ProcessFileContent(std::ifstream& fin, std::ofstream& fout, int64_t remainingSize)
{
    int64_t bytesProcessed = 0;

    while (fin.good() && fin.peek() != EOF)
    {
        // Check if we've reached the end of current GRUP
        if (remainingSize >= 0 && bytesProcessed >= remainingSize)
        {
            break;
        }

        // Read signature
        char sig[4];
        std::streampos posBeforeSig = fin.tellg();
        if (!fin.read(sig, 4)) break;

        // FIXED: Track actual bytes consumed by child functions
        std::streampos posAfterSig = fin.tellg();

        if (IsGRUP(sig))
        {
            // Process GRUP recursively
            if (!ProcessGRUP(fin, fout, sig))
            {
                std::cerr << "Error: Failed to process GRUP at position " << posBeforeSig << "\n";
                return false;
            }
        }
        else
        {
            // Process individual record
            if (!ProcessRecord(fin, fout, sig))
            {
                std::cerr << "Error: Failed to process record at position " << posBeforeSig << "\n";
                return false;
            }
        }

        // FIXED: Calculate bytes consumed by measuring stream position change
        std::streampos posAfterProcess = fin.tellg();
        int64_t consumed = static_cast<int64_t>(posAfterProcess) - static_cast<int64_t>(posBeforeSig);
        bytesProcessed += consumed;
    }

    return true;
}

/**
 * Process a GRUP record recursively
 *
 * FIXED: Proper size tracking and GRUP header update
 */
bool ProcessGRUP(std::ifstream& fin, std::ofstream& fout, const char sig[4])
{
    GroupHeader gh{};
    std::memcpy(gh.sig, sig, 4);

    // Read GRUP header
    Read(fin, gh.size);
    fin.read(gh.label, 4);
    Read(fin, gh.groupType);
    Read(fin, gh.stamp);
    Read(fin, gh.unknown);

    if (gh.size < 24)
    {
        std::cerr << "Error: Invalid GRUP size: " << gh.size << "\n";
        return false;
    }

    // Write GRUP header (will update size later if contents change)
    std::streampos grupHeaderPos = fout.tellp();
    fout.write(reinterpret_cast<char*>(&gh), sizeof(gh));

    // Remember where GRUP content starts in output
    std::streampos grupContentStart = fout.tellp();

    // Process GRUP contents recursively
    int64_t contentSize = gh.size - 24; // 24 = sizeof(GroupHeader)

    bool success = ProcessGRUPContent(fin, fout, contentSize);

    if (!success)
    {
        return false;
    }

    // Calculate actual output size
    std::streampos grupContentEnd = fout.tellp();
    uint32_t actualContentSize = static_cast<uint32_t>(grupContentEnd - grupContentStart);
    uint32_t actualGrupSize = actualContentSize + 24;

    // If size changed, update GRUP header
    if (actualGrupSize != gh.size)
    {
        std::streampos savedPos = fout.tellp();
        fout.seekp(grupHeaderPos + std::streamoff(4)); // Offset to size field
        fout.write(reinterpret_cast<char*>(&actualGrupSize), sizeof(actualGrupSize));
        fout.seekp(savedPos);
    }

    return true;
}

/**
 * Process contents within a GRUP
 *
 * FIXED: Proper byte tracking with safety fallback
 */
bool ProcessGRUPContent(std::ifstream& fin, std::ofstream& fout, int64_t contentSize)
{
    std::streampos contentStart = fin.tellg();
    int64_t bytesProcessed = 0;

    while (bytesProcessed < contentSize && fin.good())
    {
        if (contentSize - bytesProcessed < 4)
        {
            // FIXED: Ensure remaining bytes are skipped
            int64_t remaining = contentSize - bytesProcessed;
            fin.seekg(remaining, std::ios::cur);
            bytesProcessed += remaining;
            break;
        }

        char sig[4];
        std::streampos posBeforeRead = fin.tellg();
        if (!fin.read(sig, 4))
        {
            std::cerr << "Error: Failed to read signature in GRUP content\n";
            break;
        }

        if (IsGRUP(sig)) {
            // Nested GRUP
            if (!ProcessGRUP(fin, fout, sig))
            {
                return false;
            }
        }
        else {
            // Record
            if (!ProcessRecord(fin, fout, sig))
            {
                return false;
            }
        }

        // FIXED: Calculate actual bytes consumed
        std::streampos posAfterProcess = fin.tellg();
        int64_t consumed = static_cast<int64_t>(posAfterProcess - posBeforeRead);
        bytesProcessed += consumed;
    }

    // FIXED: Safety check - if we didn't consume all bytes, skip remainder
    if (bytesProcessed < contentSize)
    {
        int64_t remaining = contentSize - bytesProcessed;
        std::cerr << "Warning: Skipping " << remaining << " unprocessed bytes in GRUP\n";
        fin.seekg(remaining, std::ios::cur);
    }
    // FIXED: If we somehow consumed too many bytes, rewind
    else
    {
        if (bytesProcessed > contentSize)
        {
            int64_t excess = bytesProcessed - contentSize;
            std::cerr << "Warning: Consumed " << excess << " extra bytes, rewinding\n";
            fin.seekg(-excess, std::ios::cur);
        }
    }

    return true;
}

/**
 * Process an individual record
 *
 * FIXED: Byte-perfect copy for unmodified records
 */
bool ProcessRecord(std::ifstream& fin, std::ofstream& fout, const char sig[4])
{
    RecordHeader hdr{};
    std::memcpy(hdr.sig, sig, 4);

    // Read all fields of the record header
    Read(fin, hdr.dataSize);
    Read(fin, hdr.flags);
    Read(fin, hdr.formID);
    Read(fin, hdr.versionCtrl);
    Read(fin, hdr.version);
    Read(fin, hdr.unknown);

    // Build record key
    std::string recordKey(sig, 4);
    recordKey += ":" + std::to_string(hdr.formID);

    auto it = CurrentDocument->recordIndex.find(recordKey);

    if (it != CurrentDocument->recordIndex.end())
    {
        // Modified record - apply translations
        EspRecord* rec = &CurrentDocument->records[it->second];

        std::vector<uint8_t> originalData(hdr.dataSize);
        fin.read(reinterpret_cast<char*>(originalData.data()), hdr.dataSize);

        std::vector<uint8_t> workingData;
        bool wasCompressed = IsCompressed(hdr);

        if (wasCompressed)
        {
            uint32_t uncompressedSize;
            std::memcpy(&uncompressedSize, originalData.data(), 4);

            if (!ZlibDecompress(originalData.data() + 4,
                originalData.size() - 4,
                workingData,
                uncompressedSize))
            {
                std::cerr << "Error: Decompression failed for " << std::string(sig, 4)
                    << " FormID 0x" << std::hex << hdr.formID << std::dec << "\n";
                return false;
            }
        }
        else
        {
            workingData = originalData;
        }

        // Apply translations
        workingData = ModifySubRecords(workingData, rec);

        std::vector<uint8_t> finalData;
        if (wasCompressed)
        {
            std::vector<uint8_t> compressed;
            if (!ZlibCompress(workingData.data(), workingData.size(), compressed))
            {
                std::cerr << "Error: Compression failed for " << std::string(sig, 4)
                    << " FormID 0x" << std::hex << hdr.formID << std::dec << "\n";
                return false;
            }

            finalData.resize(4 + compressed.size());
            uint32_t uncompSize = static_cast<uint32_t>(workingData.size());
            std::memcpy(finalData.data(), &uncompSize, 4);
            std::memcpy(finalData.data() + 4, compressed.data(), compressed.size());
        }
        else
        {
            finalData = workingData;
        }

        // Update header with new size
        hdr.dataSize = static_cast<uint32_t>(finalData.size());

        // Write modified record
        fout.write(sig, 4);
        fout.write(reinterpret_cast<char*>(&hdr.dataSize), sizeof(hdr.dataSize));
        fout.write(reinterpret_cast<char*>(&hdr.flags), sizeof(hdr.flags));
        fout.write(reinterpret_cast<char*>(&hdr.formID), sizeof(hdr.formID));
        fout.write(reinterpret_cast<char*>(&hdr.versionCtrl), sizeof(hdr.versionCtrl));
        fout.write(reinterpret_cast<char*>(&hdr.version), sizeof(hdr.version));
        fout.write(reinterpret_cast<char*>(&hdr.unknown), sizeof(hdr.unknown));
        fout.write(reinterpret_cast<char*>(finalData.data()), finalData.size());
    }
    else
    {
        // FIXED: Byte-perfect copy for unmodified records
        // Read entire record (header + data) as a single block
        uint32_t totalSize = 24 + hdr.dataSize; // 24 = sizeof(RecordHeader)

        // Allocate buffer for complete record
        std::vector<uint8_t> completeRecord(totalSize);

        // Copy signature (already read)
        std::memcpy(completeRecord.data(), sig, 4);

        // Copy header fields (already read)
        std::memcpy(completeRecord.data() + 4, &hdr.dataSize, sizeof(hdr.dataSize));
        std::memcpy(completeRecord.data() + 8, &hdr.flags, sizeof(hdr.flags));
        std::memcpy(completeRecord.data() + 12, &hdr.formID, sizeof(hdr.formID));
        std::memcpy(completeRecord.data() + 16, &hdr.versionCtrl, sizeof(hdr.versionCtrl));
        std::memcpy(completeRecord.data() + 20, &hdr.version, sizeof(hdr.version));
        std::memcpy(completeRecord.data() + 22, &hdr.unknown, sizeof(hdr.unknown));

        // Read record data
        fin.read(reinterpret_cast<char*>(completeRecord.data() + 24), hdr.dataSize);

        // Write entire record as one block - byte-perfect copy
        fout.write(reinterpret_cast<char*>(completeRecord.data()), totalSize);
    }

    return true;
}

/**
 * Save ESP with translations applied
 *
 * This implementation fixes all structural risks:
 * 1. Proper byte tracking throughout the file
 * 2. Safety fallbacks for incomplete reads
 * 3. Byte-perfect copy for unmodified records
 */
bool SaveEsp(const char* SavePath)
{
    if (LastSetPath.empty())
    {
        std::cerr << "Error: No source ESP file path set\n";
        return false;
    }

    std::ifstream fin(LastSetPath, std::ios::binary);
    if (!fin.is_open())
    {
        std::cerr << "Error: Cannot open source ESP file: " << LastSetPath << "\n";
        return false;
    }

    std::ofstream fout(SavePath, std::ios::binary);
    if (!fout.is_open())
    {
        std::cerr << "Error: Cannot create output ESP file: " << SavePath << "\n";
        fin.close();
        return false;
    }

    std::cout << "Processing: " << LastSetPath << " -> " << SavePath << "\n";

    // Process file with recursive GRUP handling
    // -1 means no size limit (top level)
    bool success = ProcessFileContent(fin, fout, -1);

    fin.close();
    fout.close();

    if (success)
    {
        std::cout << "Successfully saved modified ESP to: " << SavePath << "\n";
    }
    else
    {
        std::cerr << "Failed to save ESP file\n";
        // Optionally delete incomplete output file
        // std::remove(SavePath);
    }

    return success;
}
#pragma endregion

