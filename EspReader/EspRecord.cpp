#pragma once

#include "ESPHeuristicAnalysis.cpp"

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/stat.h>
#include <dirent.h>
#endif
#include "CharacterTracker.h"

#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <algorithm>
#include <cstring>
#include <string>
#include <iostream>

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
			size_t ActualSize = 0;
			for (size_t i = 0; i < Size; ++i)
			{
				if (Bytes[i] == 0)
				{
					ActualSize = i;
					break;
				}
			}

			if (ActualSize == 0)
				ActualSize = Size;

			if (IsLikelyUTF8(Bytes, ActualSize))
			{
				return RawString(std::string(reinterpret_cast<const char*>(Bytes), ActualSize));
			}
			else
			{
				return RawString(Windows1252ToUTF8(Bytes, ActualSize));
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
	int OccurrenceIndex;
	int Index;
	bool IsModify;

	SubRecordData() : IsLocalized(false), StringID(0), OccurrenceIndex(0), Index(0), IsModify(false) {}

	std::string GetString() const
	{
		if (Data.empty()) return "";

		if (IsLocalized)
		{
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

struct TempResponseData
{
	uint32_t Emotion = 0;
	int OriginalSubIndex = -1;
};

class DialResponseNode
{
public:
	uint32_t ResponseID = 0;
	uint32_t EmotionType = 0;

	int RecordOffset = 0;
	int SubOffset = 0;

	DialResponseNode() {}
	DialResponseNode(uint32_t resId, uint32_t emotion, int recOff = 0, int subOff = 0)
		: ResponseID(resId), EmotionType(emotion), RecordOffset(recOff), SubOffset(subOff) {
	}
};

class LinkDIAL
{
public:
	DialResponseNode Head;
	std::vector<DialResponseNode> Links;
};

class EspRecord
{
public:
	std::string Sig;
	uint32_t FormID;
	uint32_t Flags;
	std::vector<SubRecordData> SubRecords;
	std::unordered_map<std::string, int> TotalOccurrenceCount;
	uint8_t LastEPFT;
	bool HasEPFT;
	int Index;
	std::string EditorID;

	uint32_t        PendingVTCK = 0;
	bool            HasPendingVTCK = false;
	uint32_t        PendingANAM = 0;
	bool            HasPendingANAM = false;
	CharacterGender PendingGenderFromACBS = CharacterGender::Unknown;
	bool            HasPendingACBS = false;

	// --- Dialogue tracking (only PrevInfoFormID is used for linking, no ParentDialFormID) ---
	uint32_t PrevInfoFormID = 0;
	bool HasDialContext = false;

	std::vector<DialResponseNode> LocalDialogues;
	std::vector<TempResponseData> TempResponses_;

	EspRecord(const char* S, uint32_t FID, uint32_t FL)
		: Sig(S, 4), FormID(FID), Flags(FL), LastEPFT(0), HasEPFT(false), Index(0), EditorID("")
	{
	}

	EspRecord(const EspRecord& other)
		: Sig(other.Sig)
		, FormID(other.FormID)
		, Flags(other.Flags)
		, SubRecords(other.SubRecords)
		, TotalOccurrenceCount(other.TotalOccurrenceCount)
		, LastEPFT(other.LastEPFT)
		, HasEPFT(other.HasEPFT)
		, Index(other.Index)
		, EditorID(other.EditorID)
		, PrevInfoFormID(other.PrevInfoFormID)
		, HasDialContext(other.HasDialContext)
		, LocalDialogues(other.LocalDialogues)
		, TempResponses_(other.TempResponses_)
	{

	}

	EspRecord& operator=(const EspRecord& other)
	{
		if (this != &other)
		{
			Sig = other.Sig;
			FormID = other.FormID;
			Flags = other.Flags;
			SubRecords = other.SubRecords;
			TotalOccurrenceCount = other.TotalOccurrenceCount;
			LastEPFT = other.LastEPFT;
			HasEPFT = other.HasEPFT;
			Index = other.Index;
			EditorID = other.EditorID;
			PrevInfoFormID = other.PrevInfoFormID;
			HasDialContext = other.HasDialContext;
			LocalDialogues = other.LocalDialogues;
			TempResponses_ = other.TempResponses_;
		}
		return *this;
	}

	bool CheckSub() const
	{
		for (size_t i = 0; i < SubRecords.size(); ++i)
		{
			const SubRecordData& Sub = SubRecords[i];
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

	bool CanTranslateSub(ESP_HeuristicAnalysis* Analysis, const EspRecord& Parent, const SubRecordData& Item)
	{
		if (Item.Data.empty())
			return false;

		if (Analysis)
		{
			bool IsValid = Analysis->IsValidTranslatableText(
				Parent.Sig,
				Item.Sig,
				Item.Data.data(),
				Item.Data.size(),
				Parent.LastEPFT
			);

			return IsValid;
		}
		else
		{
			return false;
		}
	}

	bool IsProbablyStringID(const uint8_t* data, size_t size)
	{
		if (size < 4) return false;

		uint32_t id;
		std::memcpy(&id, data, 4);

		if (id > 0x000FFFFF) return false;

		if (id == 0) return false;

		if (id < 0x3E8) return false;

		bool AllPrintable = true;
		for (int i = 0; i < 4; ++i)
		{
			if (!isprint(data[i]))
			{
				AllPrintable = false;
				break;
			}
		}

		return !AllPrintable;
	}

	inline bool IsProbablyString(const uint8_t* data, size_t size)
	{
		if (!data || size == 0)
			return false;

		if (size == 1)
		{
			uint8_t c = data[0];
			return (c >= 0x20 && c <= 0x7E);
		}

		size_t zeroCount = 0;
		for (size_t i = 0; i < size; ++i)
		{
			if (data[i] == 0)
				zeroCount++;
		}

		if (zeroCount > size / 4)
			return false;

		size_t printable = 0;
		size_t scanned = 0;

		for (size_t i = 0; i < size && data[i] != 0; ++i)
		{
			uint8_t c = data[i];
			scanned++;

			if (c >= 0x20 && c <= 0x7E)
				printable++;
			else if (c == '\n' || c == '\r' || c == '\t')
				printable++;
			else if (c >= 0x80)
				printable++;
		}

		if (printable == 0)
			return false;

		if (printable * 2 < scanned)
			return false;

		std::string temp;
		for (size_t i = 0; i < size && data[i] != 0; ++i)
			temp.push_back(static_cast<char>(data[i]));

		auto IsHexChar = [](char c)
			{
				return std::isdigit((unsigned char)c) ||
					(c >= 'a' && c <= 'f') ||
					(c >= 'A' && c <= 'F');
			};

		size_t hexLike = 0;
		for (char c : temp)
		{
			if (IsHexChar(c) || c == '-')
				hexLike++;
		}

		if (!temp.empty() && hexLike == temp.size())
			return false;

		return true;
	}


	void CollectForTracker(const std::string& SubSig, const uint8_t* DataPtr, size_t Size)
	{
		if (Sig == "NPC_" && SubSig == "ACBS" && Size >= 3)
		{
			uint8_t SexFlag = DataPtr[2];
			PendingGenderFromACBS = (SexFlag & 0x01)
				? CharacterGender::Female
				: CharacterGender::Male;
			HasPendingACBS = true;
		}
		else if (Sig == "NPC_" && SubSig == "VTCK" && Size >= 4)
		{
			std::memcpy(&PendingVTCK, DataPtr, 4);
			HasPendingVTCK = true;
		}
		else if (Sig == "INFO" && SubSig == "ANAM" && Size >= 4)
		{
			std::memcpy(&PendingANAM, DataPtr, 4);
			HasPendingANAM = true;
		}
	}

	void OnRecordBegin()
	{
		TempResponses_.clear();
		LocalDialogues.clear();
	}

	std::string G_Name;
	std::string G_VoiceType;
	CharacterGender G_Gender = CharacterGender::Unknown;

	std::vector<uint32_t> G_PendingActors;
	std::vector<uint32_t> G_PendingVoiceTypes;
	std::vector<uint32_t> G_PendingFactions;
	std::vector<uint32_t> G_PendingRaces;

	void OnSubRecord(CharacterTracker* CurrentTracker, SubRecordData Sub, const uint8_t* DataPtr, size_t Size)
	{
		if (!CurrentTracker)
			return;

		if (CurrentTracker && DataPtr && Size > 0)
		{
			CollectForTracker(Sub.Sig, DataPtr, Size);
		}

		if (Sub.Sig == "FULL" || Sub.Sig == "FNAM")
		{
			G_Name = Sub.GetString();
		}
		else if (Sub.Sig == "VTCK")
		{
			G_VoiceType = Sub.GetString();
		}
		else if (Sub.Sig == "ACBS")
		{
			G_Gender = PendingGenderFromACBS;
		}

		if (Sig == "INFO")
		{
			if (Sub.Sig == "PNAM" && Size >= 4)
			{
				std::memcpy(&PrevInfoFormID, DataPtr, 4);
			}
			else if (Sub.Sig == "TRDT")
			{
				TempResponseData NewResp;
				if (Size >= 4) std::memcpy(&NewResp.Emotion, DataPtr, 4);
				TempResponses_.push_back(NewResp);
			}
			else if (Sub.Sig == "NAM1")
			{
				if (TempResponses_.empty()) {
					TempResponseData dummy;
					TempResponses_.push_back(dummy);
				}
				TempResponses_.back().OriginalSubIndex = static_cast<int>(SubRecords.size());
			}

			if (Sub.Sig == "ANAM" && Size >= 4)
			{
				uint32_t actor;
				std::memcpy(&actor, DataPtr, 4);

				G_PendingActors.push_back(actor);
			}
			else
				if (Sub.Sig == "CTDA" && Size >= 12)
				{
					uint16_t FunctionID;
					std::memcpy(&FunctionID, DataPtr + 4, 2);

					uint32_t Param1;
					std::memcpy(&Param1, DataPtr + 8, 4);

					switch (FunctionID)
					{
					case 72: // GetIsID
						G_PendingActors.push_back(Param1);
						break;

					case 97: // GetIsVoiceType
						G_PendingVoiceTypes.push_back(Param1);
						break;

					case 32: // GetInFaction
						G_PendingFactions.push_back(Param1);
						break;

					case 69: // GetIsRace
						G_PendingRaces.push_back(Param1);
						break;
					}
				}
		}
	}

	void OnRecordFinished(
		CharacterTracker* CurrentTracker,
		unordered_map<uint32_t, std::vector<uint32_t>>* DeferredInfoLinks,
		unordered_map<uint32_t, std::vector<uint32_t>>* DeferredVoiceTypeLinks,
		unordered_map<uint32_t, std::vector<uint32_t>>* DeferredFactionLinks,
		unordered_map<uint32_t, std::vector<uint32_t>>* DeferredRaceLinks,

		const char* Str, const uint8_t* DataPtr, size_t Size)
	{
		if (Sig == "INFO" && !TempResponses_.empty())
		{
			HasDialContext = true;

			for (size_t i = 0; i < TempResponses_.size(); ++i)
			{
				DialResponseNode node(
					FormID,
					TempResponses_[i].Emotion,
					this->Index,
					TempResponses_[i].OriginalSubIndex
				);
				LocalDialogues.push_back(node);
			}
		}

		if (Sig == "NPC_")
		{
			std::string Name = G_Name;
			std::string EditorID = this->EditorID;
			std::string VoiceType = G_VoiceType;
			CharacterGender Gender = G_Gender;

			if (HasPendingACBS)
				Gender = PendingGenderFromACBS;

			auto& npc = CurrentTracker->RegisterNpc(FormID, Name, EditorID, VoiceType, Gender);

			if (HasPendingVTCK)
			{
				CurrentTracker->VoiceTypeToNPC[PendingVTCK] = FormID;
				npc.LinkedVoiceTypes.push_back(PendingVTCK);
			}

			if (!VoiceType.empty() && npc.Gender == CharacterGender::Unknown)
				npc.Gender = CharacterRecord::InferGenderFromVoiceType(VoiceType);

			{
				auto ItInfo = DeferredInfoLinks->find(FormID);
				if (ItInfo != DeferredInfoLinks->end())
				{
					for (size_t i = 0; i < ItInfo->second.size(); ++i)
					{
						npc.LinkedInfos.push_back(ItInfo->second[i]);
					}
					DeferredInfoLinks->erase(ItInfo);
				}

				auto ItFaction = DeferredFactionLinks->find(FormID);
				if (ItFaction != DeferredFactionLinks->end())
				{
					for (size_t i = 0; i < ItFaction->second.size(); ++i)
					{
						npc.LinkedFactions.push_back(ItFaction->second[i]);
					}
					DeferredFactionLinks->erase(ItFaction);
				}

				auto ItRace = DeferredRaceLinks->find(FormID);
				if (ItRace != DeferredRaceLinks->end())
				{
					for (size_t i = 0; i < ItRace->second.size(); ++i)
					{
						npc.LinkedRaces.push_back(ItRace->second[i]);
					}
					DeferredRaceLinks->erase(ItRace);
				}
			}
		}

		if (!G_PendingActors.empty() ||
			!G_PendingVoiceTypes.empty() ||
			!G_PendingFactions.empty() ||
			!G_PendingRaces.empty())
		{
			// ===== Actors =====
			for (size_t i = 0; i < G_PendingActors.size(); ++i)
			{
				uint32_t NpcID = G_PendingActors[i];

				auto It = CurrentTracker->Characters.find(NpcID);
				if (It != CurrentTracker->Characters.end())
				{
					It->second.LinkedInfos.push_back(FormID);
				}
				else
				{
					(*DeferredInfoLinks)[NpcID].push_back(FormID);
				}
			}

			// ===== VoiceTypes =====
			for (size_t i = 0; i < G_PendingVoiceTypes.size(); ++i)
			{
				uint32_t VoiceTypeFID = G_PendingVoiceTypes[i];

				auto It = CurrentTracker->VoiceTypeToNPC.find(VoiceTypeFID);
				if (It != CurrentTracker->VoiceTypeToNPC.end())
				{
					uint32_t NpcID = It->second;

					auto chr = CurrentTracker->Characters.find(NpcID);
					if (chr != CurrentTracker->Characters.end())
					{
						chr->second.LinkedVoiceTypes.push_back(VoiceTypeFID);
					}
				}
				else
				{
					(*DeferredVoiceTypeLinks)[VoiceTypeFID].push_back(FormID);
				}
			}

			// ===== Factions =====
			for (size_t i = 0; i < G_PendingFactions.size(); ++i)
			{
				uint32_t Faction = G_PendingFactions[i];

				for (size_t j = 0; j < G_PendingActors.size(); ++j)
				{
					uint32_t NpcID = G_PendingActors[j];

					auto It = CurrentTracker->Characters.find(NpcID);
					if (It != CurrentTracker->Characters.end())
					{
						It->second.LinkedFactions.push_back(Faction);
					}
					else
					{
						(*DeferredFactionLinks)[NpcID].push_back(Faction);
					}
				}
			}

			// ===== Races =====
			for (size_t i = 0; i < G_PendingRaces.size(); ++i)
			{
				uint32_t Race = G_PendingRaces[i];

				for (size_t j = 0; j < G_PendingActors.size(); ++j)
				{
					uint32_t NpcID = G_PendingActors[j];

					auto It = CurrentTracker->Characters.find(NpcID);
					if (It != CurrentTracker->Characters.end())
					{
						It->second.LinkedRaces.push_back(Race);
					}
					else
					{
						(*DeferredRaceLinks)[NpcID].push_back(Race);
					}
				}
			}
		}

		G_Name.clear();
		G_VoiceType.clear();
		G_Gender = CharacterGender::Unknown;
		G_PendingActors.clear();
		G_PendingVoiceTypes.clear();
		G_PendingFactions.clear();
		G_PendingRaces.clear();
	}
	void AddSubRecord(CharacterTracker* CurrentTracker, ESP_HeuristicAnalysis* Analysis, const char* Str, const uint8_t* DataPtr, size_t Size, RecordFilter& Filter)
	{
		SubRecordData Sub;
		Sub.Sig = std::string(Str, 4);

		int CurrentOccurrence = TotalOccurrenceCount[Sub.Sig];
		TotalOccurrenceCount[Sub.Sig]++;

		Sub.OccurrenceIndex = CurrentOccurrence;
		Sub.Index = static_cast<int>(SubRecords.size());

		//===== PERK Special Handling: Recording EPFT Value =====
		if (Sig == "PERK" && Sub.Sig == "EPFT" && DataPtr && Size >= 1)
		{
			LastEPFT = DataPtr[0];
			HasEPFT = true;
		}

		if (DataPtr && Size > 0)
		{
			Sub.Data.assign(DataPtr, DataPtr + Size);

			bool IsLocalizedField = false;

			IsLocalizedField = Size == 4 && IsProbablyStringID(DataPtr, 4);

			if (IsLocalizedField)
			{
				uint32_t StringID = 0;
				std::memcpy(&StringID, DataPtr, sizeof(uint32_t));
				Sub.StringID = StringID;

				Sub.IsLocalized = true;
			}
			else
			{
				Sub.IsLocalized = false;
				Sub.StringID = 0;
			}

			OnSubRecord(CurrentTracker, Sub, DataPtr, Size);
		}

		if (Sub.Sig == "EDID")
		{
			std::string EditorIDValue = RawString::FromBytes(Sub.Data).ToUTF8String();

			this->EditorID = EditorIDValue;

			return;
		}

		if (Filter.ShouldParseRecordWithSub(this->Sig, Sub.Sig))
		{
			if (Sub.IsLocalized == true)
			{
				SubRecords.push_back(Sub);
			}
			else
				if (CanTranslateSub(Analysis, *this, Sub))
				{
					SubRecords.push_back(Sub);
				}
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

	//This is the key for the main record, not for the sub-record!
	std::string GetUniqueKey() const
	{
		return std::to_string(FormID) + ":" + Sig;
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

	// Only InfoChildLinksMap is used (based on PrevInfoFormID)
	std::unordered_map<size_t, std::vector<size_t>> InfoChildLinksMap;
	std::unordered_map<uint32_t, uint32_t> InFoToDialMap;

	EspData() : GrupCount(0), HasTES4Header(false) {}

	void BuildDialTopologyIndex()
	{
		InfoChildLinksMap.clear();

		std::unordered_map<uint32_t, size_t> InfoFormIDToIdx;
		for (size_t i = 0; i < Records.size(); ++i)
		{
			if (Records[i].Sig == "INFO") {
				InfoFormIDToIdx[Records[i].FormID] = i;
				// Update RecordOffset for each dialogue node
				for (auto& dialogue : Records[i].LocalDialogues) {
					dialogue.RecordOffset = static_cast<int>(i);
				}
			}
		}

		for (size_t i = 0; i < Records.size(); ++i)
		{
			if (Records[i].Sig == "INFO" && Records[i].PrevInfoFormID != 0)
			{
				auto it = InfoFormIDToIdx.find(Records[i].PrevInfoFormID);
				if (it != InfoFormIDToIdx.end())
				{
					InfoChildLinksMap[it->second].push_back(i);
				}
			}
		}
	}

	size_t FindDialParentDialIndex(size_t InFoIndex)
	{
		if (InFoIndex >= Records.size()) return (size_t)-1;
		if (Records[InFoIndex].Sig != "INFO") return (size_t)-1;

		uint32_t InfoFormID = Records[InFoIndex].FormID;

		auto It = InFoToDialMap.find(InfoFormID);
		if (It == InFoToDialMap.end()) return (size_t)-1;

		uint32_t DialFormID = It->second;

		for (size_t i = 0; i < Records.size(); ++i)
		{
			if (Records[i].Sig == "DIAL" && Records[i].FormID == DialFormID)
				return i;
		}
		return (size_t)-1;
	}

	LinkDIAL* GetDialContextByIndex(int RecordOffset, int SubOffset)
	{
		try {
			if (RecordOffset < 0 || RecordOffset >= (int)Records.size())
				return nullptr;

			EspRecord& TargetRec = Records[RecordOffset];
			if (TargetRec.Sig != "INFO")
				return nullptr;

			// Find the anchor node that matches the given SubOffset
			DialResponseNode anchorNode;
			bool foundAnchor = false;
			for (const auto& d : TargetRec.LocalDialogues) {
				if (d.SubOffset == SubOffset) {
					anchorNode = d;
					foundAnchor = true;
					break;
				}
			}

			if (!foundAnchor)
				return nullptr;

			size_t RootIndex = FindDialParentDialIndex(RecordOffset);

			std::unordered_map<uint32_t, size_t> InfoFormIDToIdx;
			for (size_t i = 0; i < Records.size(); ++i)
			{
				if (Records[i].Sig == "INFO")
					InfoFormIDToIdx[Records[i].FormID] = i;
			}

			LinkDIAL* CombinedContext = new LinkDIAL();
			std::unordered_set<size_t> VisitedRecords;
			std::vector<DialResponseNode> UpstreamNodes;
			size_t CurrentUpIdx = (size_t)RecordOffset;

			// Walk backwards via PrevInfoFormID
			while (true)
			{
				uint32_t prevFormID = Records[CurrentUpIdx].PrevInfoFormID;
				if (prevFormID == 0)
					break;
				auto itPrev = InfoFormIDToIdx.find(prevFormID);
				if (itPrev == InfoFormIDToIdx.end())
					break;
				size_t prevIdx = itPrev->second;
				if (VisitedRecords.count(prevIdx))
					break;
				VisitedRecords.insert(prevIdx);
				CurrentUpIdx = prevIdx;
				if (Records[prevIdx].HasDialContext)
				{
					for (auto itSub = Records[prevIdx].LocalDialogues.rbegin(); itSub != Records[prevIdx].LocalDialogues.rend(); ++itSub) {
						UpstreamNodes.push_back(*itSub);
					}
				}
			}
			for (auto it = UpstreamNodes.rbegin(); it != UpstreamNodes.rend(); ++it)
			{
				CombinedContext->Links.push_back(*it);
			}

			// Add previous dialogues in the same record (before anchor)
			for (const auto& d : TargetRec.LocalDialogues) {
				if (d.SubOffset < SubOffset) {
					CombinedContext->Links.push_back(d);
				}
			}

			DialResponseNode HeadNode;
			HeadNode.SubOffset = 0;
			if (RootIndex != (size_t)-1)
			{
				HeadNode.RecordOffset = (int)RootIndex;
				HeadNode.ResponseID = Records[RootIndex].FormID;
			}
			else
			{
				HeadNode.RecordOffset = -1;
				HeadNode.ResponseID = 0;
			}
			HeadNode.EmotionType = 999;
			CombinedContext->Head = HeadNode;
			CombinedContext->Links.push_back(anchorNode);

			// Add subsequent dialogues in the same record (after anchor)
			for (const auto& d : TargetRec.LocalDialogues) {
				if (d.SubOffset > SubOffset) {
					CombinedContext->Links.push_back(d);
				}
			}

			// Walk forward via InfoChildLinksMap (children linked by PNAM)
			size_t WalkIdx = (size_t)RecordOffset;
			VisitedRecords.insert((size_t)RecordOffset);
			while (true)
			{
				auto itChild = InfoChildLinksMap.find(WalkIdx);
				if (itChild == InfoChildLinksMap.end() || itChild->second.empty())
					break;
				size_t NextIdx = (size_t)-1;
				for (size_t ChildIdx : itChild->second)
				{
					if (!VisitedRecords.count(ChildIdx))
					{
						NextIdx = ChildIdx;
						break;
					}
				}
				if (NextIdx == (size_t)-1)
					break;
				VisitedRecords.insert(NextIdx);
				WalkIdx = NextIdx;
				if (Records[NextIdx].HasDialContext)
				{
					for (const auto& d : Records[NextIdx].LocalDialogues) {
						CombinedContext->Links.push_back(d);
					}
				}
			}

			return CombinedContext;
		}
		catch (...) {
			return nullptr;
		}
	}

	LinkDIAL* GetDialContextByDialIndex(int RecordOffset)
	{
		try {
		if (RecordOffset < 0 || RecordOffset >= (int)Records.size())
			return nullptr;

		EspRecord& DialRec = Records[RecordOffset];
		if (DialRec.Sig != "DIAL")
			return nullptr;

		uint32_t DialFormID = DialRec.FormID;

		std::vector<size_t> TopicInfoIndices;
		for (size_t i = 0; i < Records.size(); ++i)
		{
			if (Records[i].Sig != "INFO")
				continue;

			auto ItDial = InFoToDialMap.find(Records[i].FormID);
			if (ItDial != InFoToDialMap.end() && ItDial->second == DialFormID)
				TopicInfoIndices.push_back(i);
		}

		if (TopicInfoIndices.empty())
			return nullptr;

		std::unordered_map<uint32_t, size_t> InfoFormIDToIdx;
		for (size_t Idx : TopicInfoIndices)
			InfoFormIDToIdx[Records[Idx].FormID] = Idx;

		LinkDIAL* CombinedContext = new LinkDIAL();

		DialResponseNode HeadNode;
		HeadNode.RecordOffset = RecordOffset;
		HeadNode.ResponseID = DialFormID;
		HeadNode.SubOffset = 0;
		HeadNode.EmotionType = 999;
		CombinedContext->Head = HeadNode;

		std::unordered_set<size_t> VisitedRecords;

		for (size_t RootIdx : TopicInfoIndices)
		{
			if (VisitedRecords.count(RootIdx))
				continue;

			uint32_t PrevID = Records[RootIdx].PrevInfoFormID;
			bool IsRoot = (PrevID == 0) || (InfoFormIDToIdx.find(PrevID) == InfoFormIDToIdx.end());
			if (!IsRoot)
				continue;

			size_t WalkIdx = RootIdx;
			VisitedRecords.insert(WalkIdx);

			if (Records[WalkIdx].HasDialContext)
			{
				for (const auto& d : Records[WalkIdx].LocalDialogues)
					CombinedContext->Links.push_back(d);
			}

			while (true)
			{
				auto ItChild = InfoChildLinksMap.find(WalkIdx);
				if (ItChild == InfoChildLinksMap.end() || ItChild->second.empty())
					break;

				size_t NextIdx = (size_t)-1;
				for (size_t ChildIdx : ItChild->second)
				{
					if (!VisitedRecords.count(ChildIdx))
					{
						NextIdx = ChildIdx;
						break;
					}
				}

				if (NextIdx == (size_t)-1)
					break;

				VisitedRecords.insert(NextIdx);
				WalkIdx = NextIdx;

				if (Records[WalkIdx].HasDialContext)
				{
					for (const auto& d : Records[WalkIdx].LocalDialogues)
						CombinedContext->Links.push_back(d);
				}
			}
		}

		return CombinedContext;
		}
		catch (...) {
			return nullptr;
		}
	}

	int GetTitleIndexByBookDesc(int RecordOffset, int DescSubOffset) const
	{
		try {
		if (RecordOffset < 0 || RecordOffset >= static_cast<int>(Records.size()))
			return -1;

		const EspRecord& TargetRec = Records[RecordOffset];

		if (TargetRec.Sig != "BOOK")
			return -1;

		bool IsValidDesc = false;
		for (const auto& Sub : TargetRec.SubRecords)
		{
			if (Sub.Index == DescSubOffset && Sub.Sig == "DESC")
			{
				IsValidDesc = true;
				break;
			}
		}

		if (!IsValidDesc)
			return -1;

		for (const auto& Sub : TargetRec.SubRecords)
		{
			if (Sub.Sig == "FULL")
			{
				return Sub.Index;
			}
		}

		return -1;
		}
		catch (...) {
			return -1;
		}
	}

	int GetDescIndexByBookTitle(int RecordOffset, int TitleSubOffset) const
	{
		try {
		if (RecordOffset < 0 || RecordOffset >= static_cast<int>(Records.size()))
			return -1;

		const EspRecord& TargetRec = Records[RecordOffset];

		if (TargetRec.Sig != "BOOK")
			return -1;

		bool IsValidTitle = false;
		for (const auto& Sub : TargetRec.SubRecords)
		{
			if (Sub.Index == TitleSubOffset && Sub.Sig == "FULL")
			{
				IsValidTitle = true;
				break;
			}
		}

		if (!IsValidTitle)
			return -1;

		for (const auto& Sub : TargetRec.SubRecords)
		{
			if (Sub.Sig == "DESC")
			{
				return Sub.Index;
			}
		}

		return -1;
		}
		catch (...) {
			return -1;
		}
	}

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

	void AddRecord(EspRecord& Rec, RecordFilter& Filter, uint32_t CurrentDialFormID = 0)
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
			size_t Size = CellRecords.size();

			Rec.Index = static_cast<int>(Size);

			const size_t CellIndex = Size;
			CellRecords.push_back(Rec);
			CellByFormID[Rec.FormID] = CellIndex;

			std::string EditorID = Rec.EditorID;
			if (!EditorID.empty())
			{
				CellByEditorID[EditorID] = CellIndex;
			}
		}
		else
		{
			if (Rec.Sig == "INFO")
			{
				if (CurrentDialFormID != 0) {
					InFoToDialMap[Rec.FormID] = CurrentDialFormID;
				}
			}

			if (Filter.ShouldParseRecordWithSub(Rec.Sig, ""))
			{
				Rec.Index = static_cast<int>(Records.size());

				Records.push_back(Rec);
			}
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