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
#include "StringsFileHelper.h"

// ===== Record Filter Configuration =====
class RecordFilter
{
public:
	bool AllowAll;
	RecordFilter() : AllowAll(false) {}
	void AddRecordType(const std::string& recordType, const std::vector<std::string>& subRecords)
	{
		std::string sig = recordType.substr(0, 4);
		RecordTypes_.insert(sig);

		for (size_t i = 0; i < subRecords.size(); ++i)
		{
			std::string subSig = subRecords[i].substr(0, 4);
			SubRecordFilters_[sig].insert(subSig);
		}
	}

	bool ShouldParseRecordWithSub(const std::string& ParentSig, const std::string& ChildSig) const
	{
		if (AllowAll) return true;

		auto it = SubRecordFilters_.find(ParentSig);
		if (it == SubRecordFilters_.end())
			return false;

		if (ChildSig.empty())
			return true;

		const std::unordered_set<std::string>& requiredSubs = it->second;

		if (requiredSubs.empty())
			return true;

		return requiredSubs.count(ChildSig) > 0;
	}

	std::unordered_map<std::string, std::vector<std::string>> CurrentConfig;
	void LoadFromConfig(const std::unordered_map<std::string, std::vector<std::string>>& Config)
	{
		CurrentConfig = Config;
		for (std::unordered_map<std::string, std::vector<std::string>>::const_iterator it = Config.begin();
			it != Config.end(); ++it)
		{
			AddRecordType(it->first, it->second);
		}
	}

	bool IsEnabled() const
	{
		return !RecordTypes_.empty();
	}

private:
	std::unordered_set<std::string> RecordTypes_;
	std::unordered_map<std::string, std::unordered_set<std::string>> SubRecordFilters_;
};


// Global strings manager - shared by all records
extern StringsManager* g_StringsManager;

inline std::string Windows1252ToUTF8(const uint8_t* Data, size_t Size)
{
	std::string Result;
	Result.reserve(Size * 2);

	static const uint16_t CP1252_TABLE[32] =
	{
		0x20AC,0x0081,0x201A,0x0192,0x201E,0x2026,0x2020,0x2021,
		0x02C6,0x2030,0x0160,0x2039,0x0152,0x008D,0x017D,0x008F,
		0x0090,0x2018,0x2019,0x201C,0x201D,0x2022,0x2013,0x2014,
		0x02DC,0x2122,0x0161,0x203A,0x0153,0x009D,0x017E,0x0178
	};

	for (size_t i = 0; i < Size; ++i)
	{
		uint8_t C = Data[i];
		if (C == 0) break;

		if (C < 0x80)
		{
			Result += static_cast<char>(C);
		}
		else if (C >= 0x80 && C <= 0x9F)
		{
			uint16_t Unicode = CP1252_TABLE[C - 0x80];
			if (Unicode < 0x800)
			{
				Result += static_cast<char>(0xC0 | (Unicode >> 6));
				Result += static_cast<char>(0x80 | (Unicode & 0x3F));
			}
			else
			{
				Result += static_cast<char>(0xE0 | (Unicode >> 12));
				Result += static_cast<char>(0x80 | ((Unicode >> 6) & 0x3F));
				Result += static_cast<char>(0x80 | (Unicode & 0x3F));
			}
		}
		else
		{
			Result += static_cast<char>(0xC0 | (C >> 6));
			Result += static_cast<char>(0x80 | (C & 0x3F));
		}
	}

	return Result;
}

inline bool IsLikelyUTF8(const uint8_t* Data, size_t Size)
{
	for (size_t i = 0; i < Size && Data[i] != 0; ++i)
	{
		uint8_t C = Data[i];
		if (C >= 0x80)
		{
			if ((C & 0xE0) == 0xC0)
			{
				if (i + 1 >= Size || (Data[i + 1] & 0xC0) != 0x80) return false;
				i++;
			}
			else if ((C & 0xF0) == 0xE0)
			{
				if (i + 2 >= Size || (Data[i + 1] & 0xC0) != 0x80 || (Data[i + 2] & 0xC0) != 0x80) return false;
				i += 2;
			}
			else if ((C & 0xF8) == 0xF0)
			{
				if (i + 3 >= Size || (Data[i + 1] & 0xC0) != 0x80 || (Data[i + 2] & 0xC0) != 0x80 || (Data[i + 3] & 0xC0) != 0x80) return false;
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
//https://github.com/Cutleast/sse-plugin-interface/blob/master/src%2Fsse_plugin_interface%2Fdatatypes.py#L209-L233
class RawString
{
public:
	enum StrType
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

	std::string Data;
	std::string Encoding;

	RawString() {}
	RawString(const std::string& Str, const std::string& Enc = "utf8")
		: Data(Str), Encoding(Enc)
	{
	}

	static RawString Parse(const uint8_t* Bytes, size_t Size, StrType Type)
	{
		switch (Type)
		{
		case Char:
		{
			return RawString(std::string(reinterpret_cast<const char*>(Bytes), 1));
		}
		case WChar:
		case WString:
		case WZString:
		{
			if (Size < 2) return RawString("");
			std::string Utf8;
			for (size_t i = 0; i + 1 < Size; i += 2)
			{
				uint16_t WC;
				std::memcpy(&WC, Bytes + i, 2);
				if (WC == 0) break;
				if (WC < 0x80)
				{
					Utf8 += static_cast<char>(WC);
				}
				else
				{
					if (WC < 0x800)
					{
						Utf8 += static_cast<char>(0xC0 | (WC >> 6));
						Utf8 += static_cast<char>(0x80 | (WC & 0x3F));
					}
					else
					{
						Utf8 += static_cast<char>(0xE0 | (WC >> 12));
						Utf8 += static_cast<char>(0x80 | ((WC >> 6) & 0x3F));
						Utf8 += static_cast<char>(0x80 | (WC & 0x3F));
					}
				}
			}
			return RawString(Utf8);
		}
		case BString:
		case BZString:
		case ZString:
		case String:
		default:
		{
			if (IsLikelyUTF8(Bytes, Size))
			{
				return RawString(std::string(reinterpret_cast<const char*>(Bytes), Size));
			}
			else
			{
				return RawString(Windows1252ToUTF8(Bytes, Size));
			}
		}
		}
	}

	static RawString FromBytes(const std::vector<uint8_t>& Bytes, StrType Type = String)
	{
		return Parse(Bytes.data(), Bytes.size(), Type);
	}

	std::string ToUTF8String() const { return Data; }

	std::vector<uint8_t> Dump(StrType Type) const
	{
		switch (Type)
		{
		case Char:
		case String:
		{
			return std::vector<uint8_t>(Data.begin(), Data.end());
		}
		case BZString:
		{
			std::vector<uint8_t> Result;
			Result.push_back(static_cast<uint8_t>(Data.size()));
			Result.insert(Result.end(), Data.begin(), Data.end());
			Result.push_back(0);
			return Result;
		}
		default:
		{
			throw std::runtime_error("Dump not implemented for this type");
		}
		}
	}
};

struct SubRecordData
{
	std::string Sig;
	std::vector<uint8_t> Data;
	bool IsLocalized;
	uint32_t StringID;

	SubRecordData() : IsLocalized(false), StringID(0) {}

	std::string GetString() const
	{
		if (Data.empty()) return "";

		if (IsLocalized)
		{
			if (g_StringsManager && g_StringsManager->HasString(StringID))
			{
				return g_StringsManager->GetString(StringID);
			}
			return "<StringID:" + std::to_string(StringID) + ">";
		}

		return RawString::FromBytes(Data).ToUTF8String();
	}

	std::string GetRawString() const
	{
		if (Data.empty()) return "";
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

	EspRecord(const char* S, uint32_t FID, uint32_t FL)
		: Sig(S, 4), FormID(FID), Flags(FL)
	{
	}

	bool CanTranslate() const
	{
		for (size_t i = 0; i < SubRecords.size(); ++i)
		{
			const SubRecordData& Sub = SubRecords[i];
			if (!Sub.Data.empty())
			{
				if (Sub.IsLocalized)
				{
					if (Sub.StringID != 0)
					{
						return true;
					}
				}
				else
				{
					std::string Text = Sub.GetString();
					if (!Text.empty() && HasVisibleText(Text))
					{
						return true;
					}
				}
			}
		}
		return false;
	}

	void AddSubRecord(const char* Str, const uint8_t* DataPtr, size_t Size,RecordFilter& Filter)
	{
		SubRecordData Sub;
		Sub.Sig = std::string(Str, 4);

		if (DataPtr && Size > 0)
		{
			Sub.Data.assign(DataPtr, DataPtr + Size);

			// Check if localized field
			if (g_StringsManager &&
				StringsManager::IsLocalized(Flags) &&
				StringsManager::IsLocalizedField(Sub.Sig))
			{
				Sub.IsLocalized = true;
				Sub.StringID = StringsManager::GetStringID(DataPtr, Size);
			}
			else
			{
				Sub.IsLocalized = false;
				Sub.StringID = 0;
			}
		}

		if (Filter.ShouldParseRecordWithSub(this->Sig, Sub.Sig))
		{
			SubRecords.push_back(Sub);
		}
	}

	std::vector<std::pair<std::string, std::string> > GetSubRecordValues(
		const std::unordered_map<std::string, std::vector<std::string> >& RecordSubMap) const
	{
		std::vector<std::pair<std::string, std::string> > Results;

		std::unordered_map<std::string, std::vector<std::string> >::const_iterator It = RecordSubMap.find(Sig);
		if (It == RecordSubMap.end())
		{
			return Results;
		}

		for (size_t i = 0; i < It->second.size(); ++i)
		{
			const std::string& SubSig = It->second[i];
			for (size_t j = 0; j < SubRecords.size(); ++j)
			{
				if (SubRecords[j].Sig == SubSig)
				{
					Results.push_back(std::make_pair(SubRecords[j].Sig, SubRecords[j].GetString()));
					break;
				}
			}
		}

		return Results;
	}

	bool IsCell() const
	{
		return Sig == "CELL";
	}

	std::string GetUniqueKey() const
	{
		return Sig + ":" + std::to_string(FormID);
	}

	std::string GetEditorID() const
	{
		for (size_t i = 0; i < SubRecords.size(); ++i)
		{
			if (SubRecords[i].Sig == "EDID" && !SubRecords[i].IsLocalized)
			{
				return SubRecords[i].GetString();
			}
		}
		return "";
	}

	std::string GetDisplayName() const
	{
		for (size_t i = 0; i < SubRecords.size(); ++i)
		{
			if (SubRecords[i].Sig == "FULL")
			{
				return SubRecords[i].GetString();
			}
		}
		return GetEditorID();
	}
};

class EspData
{
	public:
	std::vector<EspRecord> Records;
	std::unordered_map<std::string, size_t> RecordIndex;
	std::unordered_set<uint32_t> FormIDs;

	// CELL storage
	std::vector<EspRecord> CellRecords;
	std::unordered_map<uint32_t, size_t> CellByFormID;
	std::unordered_map<std::string, size_t> CellByEditorID;

	size_t GrupCount;
	bool HasTES4Header;

	EspData() : GrupCount(0), HasTES4Header(false) {}

	std::vector<EspRecord> SearchBySig(const std::string& ParentSig, const std::string& ChildSig = "") const
	{
		std::vector<EspRecord> Matches;

		auto MatchesRecord = [&](const EspRecord& Rec) -> bool 
		{
		
			if (ParentSig != "ALL" && Rec.Sig != ParentSig)
				return false;

			
			if (ChildSig.empty() || ChildSig == "ALL")
				return true;

			for (const auto& Sub : Rec.SubRecords)
			{
				if (Sub.Sig == ChildSig)
					return true;
			}

			return false;
			};

		for (const auto& Rec : Records)
		{
			if (MatchesRecord(Rec))
				Matches.push_back(Rec);
		}

		for (const auto& Rec : CellRecords)
		{
			if (MatchesRecord(Rec))
				Matches.push_back(Rec);
		}

		return Matches;
	}

	std::vector<EspRecord> SearchByUniqueKey(const std::string& UniqueKey) const
	{
		std::vector<EspRecord> Matches;

		for (const auto& Rec : Records)
		{
			if (Rec.GetUniqueKey() == UniqueKey)
			{
				Matches.push_back(Rec);
			}
		}

		for (const auto& Rec : CellRecords)
		{
			if (Rec.GetUniqueKey() == UniqueKey)
			{
				Matches.push_back(Rec);
			}
		}

		return Matches;
	}

	inline std::string WStringToUTF8(const std::wstring& ws)
	{
		if (ws.empty())
			return {};

		int sizeNeeded = WideCharToMultiByte(
			CP_UTF8,
			0,
			ws.c_str(),
			(int)ws.size(),
			nullptr,
			0,
			nullptr,
			nullptr
		);

		std::string result(sizeNeeded, 0);

		WideCharToMultiByte(
			CP_UTF8,
			0,
			ws.c_str(),
			(int)ws.size(),
			&result[0],
			sizeNeeded,
			nullptr,
			nullptr
		);

		return result;
	}

	std::vector<EspRecord> SearchRecords(const std::string& Query, bool ExactMatch = false) const
	{
		std::vector<EspRecord> Matches;

		auto MatchesQuery = [&](const std::string& Text) -> bool {
			if (ExactMatch) {
				return Text == Query;
			}
			else {
				// Case-insensitive fuzzy search
				std::string LowerText = Text;
				std::string LowerQuery = Query;

				std::transform(LowerText.begin(), LowerText.end(), LowerText.begin(), ::tolower);
				std::transform(LowerQuery.begin(), LowerQuery.end(), LowerQuery.begin(), ::tolower);

				return LowerText.find(LowerQuery) != std::string::npos;
			}
			};

		for (const auto& Rec : Records) {
			for (const auto& Sub : Rec.SubRecords) {
				std::string Text = Sub.GetString();
				if (!Text.empty() && MatchesQuery(Text)) {
					Matches.push_back(Rec);
					break; 
				}
			}
		}

		for (const auto& Rec : CellRecords) {
			for (const auto& Sub : Rec.SubRecords) {
				std::string Text = Sub.GetString();
				if (!Text.empty() && MatchesQuery(Text)) {
					Matches.push_back(Rec);
					break;
				}
			}
		}

		return Matches;
	}

	size_t GetRecordsSubCount() const
	{
		size_t Count = 0;
		for (const auto& Rec : Records)
		{
			for (const auto& Sub : Rec.SubRecords)
			{
				std::string Text = Sub.GetString();
				if (!Text.empty() && HasVisibleText(Text))
				{
					Count++;
				}
			}
		}
		return Count;
	}

	size_t GetCellRecordsSubCount() const
	{
		size_t Count = 0;
		for (const auto& Rec : CellRecords)
		{
			for (const auto& Sub : Rec.SubRecords)
			{
				std::string Text = Sub.GetString();
				if (!Text.empty() && HasVisibleText(Text))
				{
					Count++;
				}
			}
		}
		return Count;
	}

	void AddRecord(EspRecord& Rec, RecordFilter& Filter)
	{
		const size_t Index = Records.size();
		const std::string UniqueKey = Rec.GetUniqueKey();

		if (RecordIndex.count(UniqueKey))
		{
			std::cerr << "[Warn] Duplicate record key: " << UniqueKey << "\n";
		}
		else
		{
			RecordIndex[UniqueKey] = Index;
		}

		if (Rec.Sig == "TES4")
		{
			HasTES4Header = true;
		}

		if (!FormIDs.insert(Rec.FormID).second)
		{
			std::cerr << "[Warn] Duplicate FormID 0x"
				<< std::hex << Rec.FormID << std::dec
				<< " for record " << Rec.Sig << "\n";
		}

		// Special handling for CELL
		if (Rec.IsCell())
		{
			const size_t CellIndex = CellRecords.size();
			CellRecords.push_back(Rec);
			CellByFormID[Rec.FormID] = CellIndex;

			std::string EditorID = Rec.GetEditorID();
			if (!EditorID.empty())
			{
				CellByEditorID[EditorID] = CellIndex;
			}
		}

		if (Filter.ShouldParseRecordWithSub(Rec.Sig,""))
		{
			Records.push_back(Rec);
		}
	}

	void IncrementGrupCount()
	{
		GrupCount++;
	}

	const EspRecord* FindByUniqueKey(const std::string& Key) const
	{
		for (size_t i = 0; i < Records.size(); ++i)
		{
			if (Records[i].GetUniqueKey() == Key)
			{
				return &Records[i];
			}
		}
		return NULL;
	}

	const EspRecord* FindCellByFormID(uint32_t FormID) const
	{
		std::unordered_map<uint32_t, size_t>::const_iterator It = CellByFormID.find(FormID);
		if (It != CellByFormID.end())
		{
			return &CellRecords[It->second];
		}
		return NULL;
	}

	const EspRecord* FindCellByEditorID(const std::string& EditorID) const
	{
		std::unordered_map<std::string, size_t>::const_iterator It = CellByEditorID.find(EditorID);
		if (It != CellByEditorID.end())
		{
			return &CellRecords[It->second];
		}
		return NULL;
	}

	size_t GetCount() const
	{
		return Records.size();
	}

	size_t GetTotalCount() const
	{
		size_t Count = Records.size() + GrupCount;
		if (HasTES4Header)
		{
			Count--;
		}
		return Count;
	}

	void PrintStatistics() const
	{
		std::unordered_map<std::string, size_t> TypeCounts;
		for (size_t i = 0; i < Records.size(); ++i)
		{
			TypeCounts[Records[i].Sig]++;
		}

		std::cout << "\n=== Record Statistics ===\n";
		for (std::unordered_map<std::string, size_t>::const_iterator It = TypeCounts.begin();
			It != TypeCounts.end(); ++It)
		{
			std::cout << It->first << ": " << It->second << "\n";
		}
	}
};