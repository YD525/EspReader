#pragma once
#include <fstream>
#include <vector>
#include <string>
#include <iostream>
#include <cstdint>
#include <cstring>
#include <unordered_map>
#include <unordered_set>
#include "TextHelper.h"


// Convert Windows-1252 bytes to UTF-8 string
inline std::string Windows1252ToUTF8(const uint8_t* data, size_t size) 
{
	std::string result;
	result.reserve(size * 2); // UTF-8 may be longer

	static const uint16_t cp1252_table[32] = 
	{
		0x20AC,0x0081,0x201A,0x0192,0x201E,0x2026,0x2020,0x2021,
		0x02C6,0x2030,0x0160,0x2039,0x0152,0x008D,0x017D,0x008F,
		0x0090,0x2018,0x2019,0x201C,0x201D,0x2022,0x2013,0x2014,
		0x02DC,0x2122,0x0161,0x203A,0x0153,0x009D,0x017E,0x0178
	};

	for (size_t i = 0; i < size; ++i) 
	{
		uint8_t c = data[i];
		if (c == 0) break; // Null terminator

		if (c < 0x80) 
		{
			result += static_cast<char>(c);
		}
		else 
		if (c >= 0x80 && c <= 0x9F) 
		{
			uint16_t unicode = cp1252_table[c - 0x80];
			if (unicode < 0x800) 
			{
				result += static_cast<char>(0xC0 | (unicode >> 6));
				result += static_cast<char>(0x80 | (unicode & 0x3F));
			}
			else 
			{
				result += static_cast<char>(0xE0 | (unicode >> 12));
				result += static_cast<char>(0x80 | ((unicode >> 6) & 0x3F));
				result += static_cast<char>(0x80 | (unicode & 0x3F));
			}
		}
		else 
		{ 
			// 0xA0-0xFF
			result += static_cast<char>(0xC0 | (c >> 6));
			result += static_cast<char>(0x80 | (c & 0x3F));
		}
	}

	return result;
}

// Check if data is likely UTF-8
inline bool IsLikelyUTF8(const uint8_t* data, size_t size) 
{
	for (size_t i = 0; i < size && data[i] != 0; ++i) 
	{
		uint8_t c = data[i];
		if (c >= 0x80) 
		{
			if ((c & 0xE0) == 0xC0) 
			{ 
				// 2-byte
				if (i + 1 >= size || (data[i + 1] & 0xC0) != 0x80) return false;
				i++;
			}
			else if ((c & 0xF0) == 0xE0) 
			{ 
				// 3-byte
				if (i + 2 >= size || (data[i + 1] & 0xC0) != 0x80 || (data[i + 2] & 0xC0) != 0x80) return false;
				i += 2;
			}
			else if ((c & 0xF8) == 0xF0) 
			{ 
				// 4-byte
				if (i + 3 >= size || (data[i + 1] & 0xC0) != 0x80 || (data[i + 2] & 0xC0) != 0x80 || (data[i + 3] & 0xC0) != 0x80) return false;
				i += 3;
			}
			else
			{
				return false;
			}
		}
	}
	return true;
}

// ---------------- RawString ----------------
class RawString 
{
	public:
	enum class StrType 
	{
		Char,
		WChar,
		BZString,
		BString,
		WString,
		WZString,
		ZString,
		String,
		List
	};

	std::string data;     // UTF-8
	std::string encoding; // Original encoding info

	RawString() = default;
	RawString(const std::string& str, const std::string& enc = "utf8")
		: data(str), encoding(enc) 
	{
	}

	// Parse bytes into RawString according to type
	static RawString Parse(const uint8_t* bytes, size_t size, StrType type) 
	{
		switch (type)
		{
			case StrType::Char:
			{
				return RawString(std::string(reinterpret_cast<const char*>(bytes), 1));
			}	
			case StrType::WChar:
			case StrType::WString:
			case StrType::WZString:
			{
				if (size < 2) return RawString("");
				std::string utf8;
				for (size_t i = 0; i + 1 < size; i += 2)
				{
					uint16_t wc;
					std::memcpy(&wc, bytes + i, 2);
					if (wc == 0) break;
					if (wc < 0x80) utf8 += static_cast<char>(wc);
					else
					{
						if (wc < 0x800)
						{
							utf8 += static_cast<char>(0xC0 | (wc >> 6));
							utf8 += static_cast<char>(0x80 | (wc & 0x3F));
						}
						else
						{
							utf8 += static_cast<char>(0xE0 | (wc >> 12));
							utf8 += static_cast<char>(0x80 | ((wc >> 6) & 0x3F));
							utf8 += static_cast<char>(0x80 | (wc & 0x3F));
						}
					}	
				}
				return RawString(utf8);
			}
			case StrType::BString:
			case StrType::BZString:
			case StrType::ZString:
			case StrType::String:
			default:
			{
				if (IsLikelyUTF8(bytes, size))
				{
					return RawString(std::string(reinterpret_cast<const char*>(bytes), size));
				}
				else
				{
					return RawString(Windows1252ToUTF8(bytes, size));
				}
			}	
		}
	}

	static RawString FromBytes(const std::vector<uint8_t>& bytes, StrType type = StrType::String) 
	{
		return Parse(bytes.data(), bytes.size(), type);
	}

	std::string ToUTF8String() const { return data; }

	std::vector<uint8_t> Dump(StrType type) const
	{
		switch (type) 
		{
			case StrType::Char:
			case StrType::String:
			{
				return std::vector<uint8_t>(data.begin(), data.end());
			}
			
			case StrType::BZString: 
			{
				std::vector<uint8_t> result;
				result.push_back(static_cast<uint8_t>(data.size()));
				result.insert(result.end(), data.begin(), data.end());
				result.push_back(0);
				return result;
			}
			default:
			{
				throw std::runtime_error("Dump not implemented for this type");
			}
		}
	}
};




//https://github.com/Cutleast/sse-plugin-interface/blob/master/src%2Fsse_plugin_interface%2Fdatatypes.py#L209-L233
//I'll just use the Cutleast class~

struct SubRecordData
{
	std::string Sig;
	std::vector<uint8_t> Data;

	// Get string data with proper encoding
	std::string GetString() const
	{
		if (Data.empty()) return "";

		//Using SSEAT~ RawString
		return RawString::FromBytes(Data).ToUTF8String();
	}
};

class EspRecord 
{
	public:
	std::string Sig;
	uint32_t FormID;
	uint32_t Flags;
	std::vector<SubRecordData> SubRecords;

	EspRecord(const char* s, uint32_t fID, uint32_t fl)
		: Sig(s, 4), FormID(fID), Flags(fl)
	{
	}

	bool CanTranslate() const
	{
		for (const auto& Sub : SubRecords)
		{
			if (!Sub.Data.empty())
			{
				std::string Text = Sub.GetString();

				if (!Text.empty())
				{
					if (HasVisibleText(Text))
					{
						return true;
					}
				}
			}
		}
		return false;
	}

	void AddSubRecord(const char* Str, const uint8_t* Data, size_t Size)
	{
		SubRecordData sub;
		sub.Sig = std::string(Str, 4);
		if (Data && Size > 0)
			sub.Data.assign(Data, Data + Size);
		SubRecords.push_back(std::move(sub));
	}

	std::vector<std::pair<std::string, std::string>> GetSubRecordValues(
		const std::unordered_map<std::string, std::vector<std::string>>& recordSubMap) const
	{
		std::vector<std::pair<std::string, std::string>> results;

		auto it = recordSubMap.find(Sig);
		if (it == recordSubMap.end())
		{
			return results;
		}

		for (const auto& subSig : it->second)
		{
			for (const auto& sub : SubRecords)
			{
				if (sub.Sig == subSig)
				{
					results.emplace_back(sub.Sig, sub.GetString());
					break;
				}
			}
		}

		return results;
	}

	// Check if this is a CELL record
	bool IsCell() const
	{
		return Sig == "CELL";
	}

	std::string GetUniqueKey() const
	{
		// For other records, FormID should be unique
		return Sig + ":" + std::to_string(FormID);
	}
};

class EspData
{
	public:
	std::vector<EspRecord> Records;
	std::unordered_map<std::string, size_t> RecordIndex;
	std::unordered_set<uint32_t> FormIDs;
	std::unordered_map<std::string, std::vector<size_t>> CellRecords;
	size_t GrupCount;
	bool HasTES4Header;

	EspData() : GrupCount(0), HasTES4Header(false) {}


	void AddRecord(EspRecord&& rec)
	{
		const size_t index = Records.size();
		const std::string UniqueKey = rec.GetUniqueKey();

		if (RecordIndex.count(UniqueKey))
		{
			std::cerr << "[Warn] Duplicate record key: " << UniqueKey << "\n";
		}
		else
		{
			RecordIndex.emplace(UniqueKey, index);
		}

		if (rec.Sig == "TES4")
		{
			HasTES4Header = true;
		}

		if (!FormIDs.insert(rec.FormID).second)
		{
			std::cerr << "[Warn] Duplicate FormID 0x"
				<< std::hex << rec.FormID << std::dec
				<< " for record " << rec.Sig << "\n";
		}

		if (rec.IsCell())
		{
			CellRecords[UniqueKey].push_back(index);
		}

		Records.push_back(std::move(rec));
	}

	void IncrementGrupCount()
	{
		GrupCount++;
	}

	// Find Record by Editor ID
	const EspRecord* FindByUniqueKey(const std::string& key) const
	{
		for (const auto& rec : Records)
		{
			if (rec.GetUniqueKey() == key)
			{
				return &rec;
			}
		}

		return nullptr;
	}

	size_t GetCount() const
	{
		return Records.size();
	}

	// TES5Edit counts Records + GRUPs (excluding TES4 header)
	size_t GetTotalCount() const
	{
		size_t Count = Records.size() + GrupCount;
		if (HasTES4Header)
		{
			Count--; // Exclude TES4 header from count
		}
		return Count;
	}

	// Print statistics
	void PrintStatistics() const
	{
		std::unordered_map<std::string, size_t> TypeCounts;
		for (const auto& Rec : Records)
		{
			TypeCounts[Rec.Sig]++;
		}

		std::cout << "\n=== Record Statistics ===\n";
		for (const auto& pair : TypeCounts)
		{
			std::cout << pair.first << ": " << pair.second << "\n";
		}
		std::cout << "Total Records: " << Records.size() << "\n";
		std::cout << "Total GRUPs: " << GrupCount << "\n";
		std::cout << "Total (Records + GRUPs";
		if (HasTES4Header)
		{
			std::cout << ", excluding TES4 header";
		}
		std::cout << "): " << GetTotalCount() << "\n";

		// Check for CELL conflicts
		size_t CellConflicts = 0;
		for (const auto& CellRecord : CellRecords)
		{
			if (CellRecord.second.size() > 1)
			{
				CellConflicts++;
				std::cout << "Warning: CELL '" << CellRecord.first << "' has "
					<< CellRecord.second.size() << " records\n";
			}
		}
		if (CellConflicts > 0)
		{
			std::cout << "Total CELL conflicts: " << CellConflicts << "\n";
		}
	}
};