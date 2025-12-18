#pragma once
#include <fstream>
#include <vector>
#include <string>
#include <iostream>
#include <cstdint>
#include <cstring>
#include <unordered_map>
#include <unordered_set>

// Windows-1252 to UTF-8 conversion helper
inline std::string Windows1252ToUTF8(const uint8_t* data, size_t size) {
    std::string result;
    result.reserve(size * 2); // UTF-8 might be longer

    for (size_t i = 0; i < size; ++i) {
        uint8_t c = data[i];

        if (c == 0) break; // Null terminator

        if (c < 0x80) {
            // ASCII - direct copy
            result += static_cast<char>(c);
        }
        else if (c >= 0x80 && c <= 0x9F) {
            // Windows-1252 special characters (0x80-0x9F)
            static const uint16_t cp1252_table[] = {
                0x20AC, 0x0081, 0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021,
                0x02C6, 0x2030, 0x0160, 0x2039, 0x0152, 0x008D, 0x017D, 0x008F,
                0x0090, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014,
                0x02DC, 0x2122, 0x0161, 0x203A, 0x0153, 0x009D, 0x017E, 0x0178
            };
            uint16_t unicode = cp1252_table[c - 0x80];

            // Convert to UTF-8
            if (unicode < 0x800) {
                result += static_cast<char>(0xC0 | (unicode >> 6));
                result += static_cast<char>(0x80 | (unicode & 0x3F));
            }
            else {
                result += static_cast<char>(0xE0 | (unicode >> 12));
                result += static_cast<char>(0x80 | ((unicode >> 6) & 0x3F));
                result += static_cast<char>(0x80 | (unicode & 0x3F));
            }
        }
        else {
            // 0xA0-0xFF: Latin-1 to UTF-8
            result += static_cast<char>(0xC0 | (c >> 6));
            result += static_cast<char>(0x80 | (c & 0x3F));
        }
    }

    return result;
}

// Check if data is likely UTF-8
inline bool IsLikelyUTF8(const uint8_t* data, size_t size) {
    for (size_t i = 0; i < size && data[i] != 0; ++i) {
        uint8_t c = data[i];
        if (c >= 0x80) {
            // Check for valid UTF-8 sequences
            if ((c & 0xE0) == 0xC0) { // 2-byte sequence
                if (i + 1 >= size || (data[i + 1] & 0xC0) != 0x80) return false;
                i += 1;
            }
            else if ((c & 0xF0) == 0xE0) { // 3-byte sequence
                if (i + 2 >= size || (data[i + 1] & 0xC0) != 0x80 || (data[i + 2] & 0xC0) != 0x80) return false;
                i += 2;
            }
            else if ((c & 0xF8) == 0xF0) { // 4-byte sequence
                if (i + 3 >= size || (data[i + 1] & 0xC0) != 0x80 || (data[i + 2] & 0xC0) != 0x80 || (data[i + 3] & 0xC0) != 0x80) return false;
                i += 3;
            }
            else {
                return false; // Invalid UTF-8
            }
        }
    }
    return true;
}

struct SubRecordData {
    std::string sig;
    std::vector<uint8_t> data;

    bool IsText() const {
        static const std::unordered_set<std::string> textSigs = {
            "EDID","FULL","DESC","NAME","TEXT",
            "MODL","ICON","NNAM","FNAM","RNAM","TNAM"
        };
        return textSigs.find(sig) != textSigs.end();
    }

    // Get string data with proper encoding
    std::string GetString() const 
    {
        if (data.empty()) return "";

        if (IsText()) 
        {

            if (IsLikelyUTF8(data.data(), data.size())) {
                return std::string(reinterpret_cast<const char*>(data.data()),
                    strnlen(reinterpret_cast<const char*>(data.data()), data.size()));
            }

            //Force -> UTF-8
            return Windows1252ToUTF8(data.data(), data.size());
        }

        return std::string(reinterpret_cast<const char*>(data.data()), data.size());
    }
};

class EspRecord {
public:
    std::string sig;
    uint32_t formID;
    uint32_t flags;
    std::vector<SubRecordData> subRecords;

    EspRecord(const char* s, uint32_t fID, uint32_t fl)
        : sig(s, 4), formID(fID), flags(fl) {
    }

    void AddSubRecord(const char* s, const uint8_t* data, size_t size) {
        SubRecordData sub;
        sub.sig = std::string(s, 4);
        if (data && size > 0)
            sub.data.assign(data, data + size);
        subRecords.push_back(std::move(sub));
    }

    // Get EDID (Editor ID) if exists
    std::string GetEditorID() const {
        for (const auto& sub : subRecords) {
            if (sub.sig == "EDID") {
                return sub.GetString();
            }
        }
        return "";
    }

    // Get FULL (Display Name) if exists
    std::string GetFullName() const {
        for (const auto& sub : subRecords) {
            if (sub.sig == "FULL") {
                return sub.GetString();
            }
        }
        return "";
    }

    std::vector<std::string> GetFullNames(std::unordered_map<std::string, std::vector<std::string>> recordFullMap) const 
    {
        std::vector<std::string> results;

        auto it = recordFullMap.find(sig);
        if (it == recordFullMap.end()) {
            // 默认只返回 FULL
            for (const auto& sub : subRecords) {
                if (sub.sig == "FULL") {
                    results.push_back(sub.GetString()); // 强制 UTF-8
                    break;
                }
            }
            return results;
        }

        // 遍历优先列表，按顺序返回所有匹配子记录
        for (const auto& subSig : it->second) {
            for (const auto& sub : subRecords) {
                if (sub.sig == subSig) {
                    results.push_back(sub.GetString()); // 强制 UTF-8
                    break; // 一旦找到就跳出内层循环，按优先顺序
                }
            }
        }

        return results;
    }

    // Check if this is a CELL record
    bool IsCell() const {
        return sig == "CELL";
    }

    // Get unique key for this record
    std::string GetUniqueKey() const {
        // For CELL records, use EDID + FormID to avoid conflicts
        if (IsCell()) {
            std::string edid = GetEditorID();
            if (!edid.empty()) {
                return sig + ":" + edid + ":" + std::to_string(formID);
            }
        }

        // For other records, FormID should be unique
        return sig + ":" + std::to_string(formID);
    }

    size_t GetTotalCount() const {
        return 1; // Only count main records, not subrecords
    }
};

class EspDocument {
public:
    std::vector<EspRecord> records;
    std::unordered_map<std::string, size_t> recordIndex;
    std::unordered_set<uint32_t> formIDs;
    std::unordered_map<std::string, std::vector<size_t>> cellRecords;
    size_t grupCount;
    bool hasTES4Header;

    EspDocument() : grupCount(0), hasTES4Header(false) {}

    void AddRecord(EspRecord&& rec) {
        std::string key = rec.GetUniqueKey();

        // Track if this is the TES4 header
        if (rec.sig == "TES4") {
            hasTES4Header = true;
        }

        // Check for FormID conflicts
        if (formIDs.count(rec.formID) > 0) {
            std::cerr << "Warning: Duplicate FormID 0x" << std::hex << rec.formID
                << std::dec << " for record " << rec.sig << "\n";
        }
        formIDs.insert(rec.formID);

        // Track CELL records separately
        if (rec.IsCell()) {
            std::string edid = rec.GetEditorID();
            if (!edid.empty()) {
                cellRecords[edid].push_back(records.size());
            }
        }

        // Check for key conflicts
        if (recordIndex.count(key) > 0) {
            std::cerr << "Warning: Duplicate key '" << key << "'\n";
        }

        recordIndex[key] = records.size();
        records.push_back(std::move(rec));
    }

    void IncrementGrupCount() {
        grupCount++;
    }

    // Find record by FormID
    const EspRecord* FindByFormID(uint32_t formID) const {
        for (const auto& rec : records) {
            if (rec.formID == formID) return &rec;
        }
        return nullptr;
    }

    // Find CELL records by Editor ID
    std::vector<const EspRecord*> FindCellsByEditorID(const std::string& edid) const {
        std::vector<const EspRecord*> result;
        auto it = cellRecords.find(edid);
        if (it != cellRecords.end()) {
            for (size_t idx : it->second) {
                result.push_back(&records[idx]);
            }
        }
        return result;
    }

    size_t GetCount() const {
        return records.size();
    }

    // TES5Edit counts Records + GRUPs (excluding TES4 header)
    size_t GetTotalCount() const {
        size_t count = records.size() + grupCount;
        if (hasTES4Header) {
            count--; // Exclude TES4 header from count
        }
        return count;
    }

    // Print statistics
    void PrintStatistics() const {
        std::unordered_map<std::string, size_t> typeCounts;
        for (const auto& rec : records) {
            typeCounts[rec.sig]++;
        }

        std::cout << "\n=== Record Statistics ===\n";
        for (const auto& pair : typeCounts) {
            std::cout << pair.first << ": " << pair.second << "\n";
        }
        std::cout << "Total Records: " << records.size() << "\n";
        std::cout << "Total GRUPs: " << grupCount << "\n";
        std::cout << "Total (Records + GRUPs";
        if (hasTES4Header) {
            std::cout << ", excluding TES4 header";
        }
        std::cout << "): " << GetTotalCount() << "\n";

        // Check for CELL conflicts
        size_t cellConflicts = 0;
        for (const auto& pair : cellRecords) {
            if (pair.second.size() > 1) {
                cellConflicts++;
                std::cout << "Warning: CELL '" << pair.first << "' has "
                    << pair.second.size() << " records\n";
            }
        }
        if (cellConflicts > 0) {
            std::cout << "Total CELL conflicts: " << cellConflicts << "\n";
        }
    }
};