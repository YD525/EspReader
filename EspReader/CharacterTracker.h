#pragma once
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <cstdint>
#include <algorithm>
#include <iostream>

enum class CharacterGender
{
    Unknown,
    Male,
    Female
};

struct InfoCharacterLink
{
    uint32_t InfoFormID;
    std::string RecordSig;                  
};

class CharacterRecord
{
    public:
    uint32_t        NpcFormID;      
    std::string     Name;           
    std::string     EditorID;       
    std::string     VoiceType;     
    CharacterGender Gender;             
    std::vector<uint32_t> LinkedInfos;
    std::vector<uint32_t> LinkedFactions;    
    std::vector<uint32_t> LinkedRaces;       
    std::vector<uint32_t> LinkedVoiceTypes; 


    CharacterRecord()
        : NpcFormID(0)
        , Gender(CharacterGender::Unknown)
    {
    }

    static CharacterGender InferGenderFromVoiceType(const std::string& VoiceType)
    {
        if (VoiceType.empty()) return CharacterGender::Unknown;

        std::string Lower = VoiceType;
        std::transform(Lower.begin(), Lower.end(), Lower.begin(), ::tolower);

        if (Lower.find("female") != std::string::npos)
            return CharacterGender::Female;
        if (Lower.find("male") != std::string::npos)
            return CharacterGender::Male;

        return CharacterGender::Unknown;
    }


    static CharacterGender InferGenderFromFlags(uint32_t Flags)
    {
        return (Flags & 0x000001) ? CharacterGender::Female : CharacterGender::Male;
    }

    std::string GenderString() const
    {
        switch (Gender)
        {
        case CharacterGender::Male:    return "Male";
        case CharacterGender::Female:  return "Female";
        default:                       return "Unknown";
        }
    }
};

class CharacterTracker
{
    public:
    std::unordered_map<uint32_t, CharacterRecord> Characters;
    std::unordered_map<uint32_t, uint32_t> VoiceTypeToNPC;

    CharacterRecord& RegisterNpc(uint32_t NpcFormID, const std::string& Name,
        const std::string& EditorID, const std::string& VoiceType,
        CharacterGender Gender)
    {
        auto& Record = Characters[NpcFormID];
        Record.NpcFormID = NpcFormID;

        if (!Name.empty())      Record.Name = Name;
        if (!EditorID.empty())  Record.EditorID = EditorID;
        if (!VoiceType.empty()) Record.VoiceType = VoiceType;

        Record.Gender = Gender;
        Record.LinkedInfos.clear();
        Record.LinkedFactions.clear();
        Record.LinkedRaces.clear();
        Record.LinkedVoiceTypes.clear();

        return Record;
    }

    std::vector<const CharacterRecord*> GetByGender(CharacterGender gender) const
    {
        std::vector<const CharacterRecord*> result;
        for (const auto& pair : Characters)
        {
            if (pair.second.Gender == gender)
                result.push_back(&pair.second);
        }
        return result;
    }

    std::vector<const CharacterRecord*> SearchByName(const std::string& Query) const
    {
        std::vector<const CharacterRecord*> Result;
        std::string LowerQuery = Query;
        std::transform(LowerQuery.begin(), LowerQuery.end(), LowerQuery.begin(), ::tolower);

        for (const auto& pair : Characters)
        {
            std::string LowerName = pair.second.Name;
            std::transform(LowerName.begin(), LowerName.end(), LowerName.begin(), ::tolower);

            if (LowerName.find(LowerQuery) != std::string::npos)
                Result.push_back(&pair.second);
        }

        return Result;
    }

    size_t TotalCharacters() const { return Characters.size(); }

    void Clear()
    {
        Characters.clear();
    }
};