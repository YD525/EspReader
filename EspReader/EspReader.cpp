#include <fstream>
#include <vector>
#include <string>
#include <iostream>
#include <cstdint>
#include <stack>
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

// Parse subrecords from memory buffer
void ParseSubRecords(const uint8_t* data, size_t dataSize, EspRecord& rec)
{
    size_t offset = 0;
    while (offset + sizeof(SubRecordHeader) <= dataSize) {
        const SubRecordHeader* sub = reinterpret_cast<const SubRecordHeader*>(data + offset);
        if (offset + sizeof(SubRecordHeader) + sub->size > dataSize) break;
        rec.AddSubRecord(sub->sig, data + offset + sizeof(SubRecordHeader), sub->size);
        offset += sizeof(SubRecordHeader) + sub->size;
    }
}

// Parse subrecords from stream
void ParseSubRecordsStream(std::ifstream& f, uint32_t recordSize, EspRecord& rec)
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
        rec.AddSubRecord(sub.sig, buf.data(), sub.size);
    }
}

// Parse a single record
void ParseRecord(std::ifstream& f, const char sig[4], EspDocument& doc)
{
    RecordHeader hdr{};
    std::memcpy(hdr.sig, sig, 4);
    Read(f, hdr.dataSize);
    Read(f, hdr.flags);
    Read(f, hdr.formID);
    Read(f, hdr.versionCtrl);
    Read(f, hdr.version);
    Read(f, hdr.unknown);

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
            ParseSubRecords(decompressed.data(), decompressed.size(), rec);
    }
    else {
        ParseSubRecordsStream(f, hdr.dataSize, rec);
    }

    doc.AddRecord(std::move(rec));
}

// Iterative group parsing
void ParseGroupIterative(std::ifstream& f, EspDocument& doc)
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
                        ParseSubRecords(decompressed.data(), decompressed.size(), rec);
                }
            }
            else {
                ParseSubRecordsStream(f, hdr.dataSize, rec);
            }

            doc.AddRecord(std::move(rec));
            state.remaining -= recordTotalSize;
        }
    }
}

// Read ESP
int ReadEsp(const char* EspPath, EspDocument& doc)
{
    std::ifstream f(EspPath, std::ios::binary);
    if (!f.is_open()) {
        std::cerr << "Failed to open ESP: " << EspPath << "\n";
        return 1;
    }

    while (f.good() && f.peek() != EOF) {
        char sig[4];
        if (!f.read(sig, 4)) break;

        if (IsGRUP(sig)) {
            ParseGroupIterative(f, doc);
        }
        else {
            ParseRecord(f, sig, doc);
        }
    }
    return 0;
}

int main()
{
    EspDocument doc;
    const char* EspPath = "C:\\Users\\52508\\Desktop\\1TestMod\\Skyrim.esm";

    std::cout << "Starting ESP parsing...\n";
    int state = ReadEsp(EspPath, doc);

    if (state == 0) {
        std::cout << "Finished reading ESP.\n";
        std::cout << "Total records: " << doc.GetTotalCount() << "\n";

        // Print statistics
        doc.PrintStatistics();

        // Example: Find a specific record
        auto cellRecs = doc.FindCellsByEditorID("WhiterunWorld");
        if (!cellRecs.empty()) {
            std::cout << "\nFound " << cellRecs.size()
                << " CELL records with EDID 'WhiterunWorld'\n";
        }
    }
    else {
        std::cerr << "Failed to read ESP\n";
    }

    return 0;
}