#include <fstream>
#include <vector>
#include <string>
#include <iostream>
#include <cstdint>
#include <stack>
#include "miniz.h"

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

// Read helper
template<typename T>
inline void Read(std::ifstream& f, T& out) { f.read(reinterpret_cast<char*>(&out), sizeof(T)); }
inline bool IsGRUP(const char sig[4]) { return std::memcmp(sig, "GRUP", 4) == 0; }
bool IsCompressed(const RecordHeader& hdr) { return (hdr.flags & RECORD_FLAG_COMPRESSED) != 0; }

bool ZlibDecompress(const uint8_t* src, size_t srcSize, std::vector<uint8_t>& out, size_t uncompressedSize)
{
    out.resize(uncompressedSize);
    size_t ret = tinfl_decompress_mem_to_mem(out.data(), uncompressedSize, src, srcSize, TINFL_FLAG_PARSE_ZLIB_HEADER);
    if (ret != uncompressedSize) {
        std::cerr << "Decompression failed, expected size: " << uncompressedSize << ", got: " << ret << "\n";
        return false;
    }
    return true;
}

// Parse subrecords from memory buffer
void ParseSubRecords(const uint8_t* data, size_t dataSize)
{
    size_t offset = 0;
    while (offset + sizeof(SubRecordHeader) <= dataSize) {
        const SubRecordHeader* sub = reinterpret_cast<const SubRecordHeader*>(data + offset);
        std::string name(sub->sig, 4);
        if (sub->size == 0 || offset + sizeof(SubRecordHeader) + sub->size > dataSize) break;
        std::cout << "  Sub: " << name << " Size=" << sub->size << "\n";
        offset += sizeof(SubRecordHeader) + sub->size;
    }
}

// Parse subrecords directly from stream
void ParseSubRecordsStream(std::ifstream& f, uint32_t recordSize)
{
    uint32_t bytesRead = 0;
    while (bytesRead + sizeof(SubRecordHeader) <= recordSize && f.good()) {
        SubRecordHeader sub{};
        if (!f.read(reinterpret_cast<char*>(&sub), sizeof(sub))) break;
        if (sub.size == 0 || bytesRead + sizeof(SubRecordHeader) + sub.size > recordSize) {
            std::cerr << "Invalid subrecord size, skipping rest of record\n";
            f.seekg(recordSize - bytesRead - sizeof(SubRecordHeader), std::ios::cur);
            break;
        }
        std::string subName(sub.sig, 4);
        std::cout << "  Sub: " << subName << " Size=" << sub.size << "\n";
        if (sub.size > 0) f.seekg(sub.size, std::ios::cur);
        bytesRead += sizeof(SubRecordHeader) + sub.size;
    }
}

// Parse a single record
void ParseRecord(std::ifstream& f, const char sig[4])
{
    RecordHeader hdr{};
    std::memcpy(hdr.sig, sig, 4);
    Read(f, hdr.dataSize); Read(f, hdr.flags); Read(f, hdr.formID);
    Read(f, hdr.versionCtrl); Read(f, hdr.version); Read(f, hdr.unknown);

    std::string name(hdr.sig, 4);
    std::cout << "Record: " << name
        << " Size=" << hdr.dataSize
        << " FormID=0x" << std::hex << hdr.formID << std::dec << "\n";

    if (IsCompressed(hdr)) {
        if (hdr.dataSize < 4) { f.seekg(hdr.dataSize, std::ios::cur); return; }
        uint32_t uncompressedSize{};
        Read(f, uncompressedSize);
        uint32_t compressedSize = hdr.dataSize - 4;
        if (compressedSize == 0) return;
        std::vector<uint8_t> compressed(compressedSize);
        f.read(reinterpret_cast<char*>(compressed.data()), compressedSize);
        std::vector<uint8_t> decompressed;
        if (ZlibDecompress(compressed.data(), compressedSize, decompressed, uncompressedSize))
            ParseSubRecords(decompressed.data(), decompressed.size());
        else
            std::cerr << "Zlib decompress failed for record " << name << "\n";
        return;
    }

    ParseSubRecordsStream(f, hdr.dataSize);
}

// Iterative group parsing using a stack
void ParseGroupIterative(std::ifstream& f)
{
    struct GroupState { std::streampos startPos; uint32_t remaining; };

    std::stack<GroupState> groupStack;

    // Read first group header
    GroupHeader gh;
    Read(f, gh.size); f.read(gh.label, 4); Read(f, gh.groupType); Read(f, gh.stamp); Read(f, gh.unknown);
    std::cout << "Group: " << std::string(gh.label, 4)
        << " Size=" << gh.size
        << " Type=" << gh.groupType << "\n";

    groupStack.push({ f.tellg(), gh.size - 24 }); // subtract header after sig

    while (!groupStack.empty()) {
        auto& state = groupStack.top();
        if (state.remaining == 0) { groupStack.pop(); continue; }

        char sig[4];
        if (!f.read(sig, 4)) { groupStack.pop(); continue; }

        uint32_t consumed = 4;
        if (IsGRUP(sig)) {
            // New group
            Read(f, gh.size); f.read(gh.label, 4); Read(f, gh.groupType); Read(f, gh.stamp); Read(f, gh.unknown);
            std::cout << "Group: " << std::string(gh.label, 4)
                << " Size=" << gh.size
                << " Type=" << gh.groupType << "\n";
            consumed += 24;
            groupStack.push({ f.tellg(), gh.size - 24 });
        }
        else {
            // Record
            ParseRecord(f, sig);
            consumed += 0; // record size consumed is managed inside ParseRecord
        }

        state.remaining -= consumed;
    }
}

int ReadEsp(char* EspPath, bool EnableLog)
{
    std::ifstream f(EspPath, std::ios::binary);
    if (!f.is_open()) { if (EnableLog) std::cerr << "Failed to open esp file: " << EspPath << "\n"; return 1; }
    if (EnableLog) std::cout << "Reading ESP: " << EspPath << "\n";

    while (f.good()) {
        char sig[4];
        if (!f.read(sig, 4)) break;
        if (IsGRUP(sig)) ParseGroupIterative(f);
        else ParseRecord(f, sig);
    }
    return 0;
}

int main()
{
    const char* EspPath =
        "C:\\Users\\52508\\Desktop\\1TestMod\\Interesting NPCs - 4.5 to 4.54 Update-29194-4-54-1681353795\\Data\\3DNPC.esp";
    ReadEsp((char*)EspPath, true);
    std::cout << "Finished reading ESP.\n";
    return 0;
}
