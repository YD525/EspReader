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

struct RecordRef
{
    uint32_t    FormID;         
    std::string RecordSig;     
    std::string SubSig;       
    std::string TextSnippet;   
    int         RecordIndex;   

    RecordRef()
        : FormID(0)
        , RecordIndex(-1)
    {
    }

    RecordRef(uint32_t fid, const std::string& sig,
        const std::string& sub = "",
        const std::string& snippet = "",
        int index = -1)
        : FormID(fid)
        , RecordSig(sig)
        , SubSig(sub)
        , TextSnippet(snippet.size() > 64 ? snippet.substr(0, 64) + "..." : snippet)
        , RecordIndex(index)
    {
    }
};


class CharacterRecord
{
public:
    uint32_t        NpcFormID;      
    std::string     Name;           
    std::string     EditorID;       
    std::string     VoiceType;     
    CharacterGender Gender;         
    bool            IsGeneric;      

    std::vector<RecordRef> AssociatedRefs; 

    CharacterRecord()
        : NpcFormID(0)
        , Gender(CharacterGender::Unknown)
        , IsGeneric(false)
    {
    }

    static CharacterGender InferGenderFromVoiceType(const std::string& voiceType)
    {
        if (voiceType.empty()) return CharacterGender::Unknown;

        std::string lower = voiceType;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

        if (lower.find("female") != std::string::npos)
            return CharacterGender::Female;
        if (lower.find("male") != std::string::npos)
            return CharacterGender::Male;

        return CharacterGender::Unknown;
    }


    static CharacterGender InferGenderFromFlags(uint32_t acbsFlags)
    {
        return (acbsFlags & 0x000001) ? CharacterGender::Female : CharacterGender::Male;
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

    void AddRef(const RecordRef& ref)
    {
        for (const auto& existing : AssociatedRefs)
        {
            if (existing.FormID == ref.FormID && existing.SubSig == ref.SubSig)
                return;
        }
        AssociatedRefs.push_back(ref);
    }

    std::vector<RecordRef> GetRefsBySig(const std::string& sig) const
    {
        std::vector<RecordRef> result;
        for (const auto& ref : AssociatedRefs)
        {
            if (ref.RecordSig == sig)
                result.push_back(ref);
        }
        return result;
    }
};

class CharacterTracker
{
    public:
    std::unordered_map<uint32_t, CharacterRecord> Characters;

    std::unordered_map<std::string, CharacterRecord> GenericCharacters;

    std::unordered_map<uint32_t, std::vector<uint32_t>> InfoToNpcMap;

    CharacterRecord& RegisterNpc(uint32_t npcFormID,
        const std::string& name,
        const std::string& editorID,
        const std::string& voiceType,
        CharacterGender gender = CharacterGender::Unknown)
    {
        auto& rec = Characters[npcFormID];
        rec.NpcFormID = npcFormID;

        if (!name.empty())      rec.Name = name;
        if (!editorID.empty())  rec.EditorID = editorID;
        if (!voiceType.empty()) rec.VoiceType = voiceType;

        if (!voiceType.empty())
            rec.Gender = CharacterRecord::InferGenderFromVoiceType(voiceType);
        else if (gender != CharacterGender::Unknown)
            rec.Gender = gender;

        return rec;
    }

    void LinkRefToNpc(uint32_t npcFormID, const RecordRef& ref)
    {
        auto it = Characters.find(npcFormID);
        if (it != Characters.end())
        {
            it->second.AddRef(ref);
        }
    }


    void LinkInfoToNpc(uint32_t infoFormID, uint32_t npcFormID,
        const std::string& textSnippet = "",
        int recordIndex = -1)
    {
        InfoToNpcMap[infoFormID].push_back(npcFormID);

        RecordRef ref(infoFormID, "INFO", "NAM1", textSnippet, recordIndex);
        LinkRefToNpc(npcFormID, ref);
    }

    std::vector<const CharacterRecord*> GetCharactersForInfo(uint32_t infoFormID) const
    {
        std::vector<const CharacterRecord*> result;

        auto it = InfoToNpcMap.find(infoFormID);
        if (it == InfoToNpcMap.end())
            return result;

        for (uint32_t npcFid : it->second)
        {
            auto charIt = Characters.find(npcFid);
            if (charIt != Characters.end())
                result.push_back(&charIt->second);
        }

        return result;
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

    std::vector<const CharacterRecord*> SearchByName(const std::string& query) const
    {
        std::vector<const CharacterRecord*> result;
        std::string lowerQuery = query;
        std::transform(lowerQuery.begin(), lowerQuery.end(), lowerQuery.begin(), ::tolower);

        for (const auto& pair : Characters)
        {
            std::string lowerName = pair.second.Name;
            std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);

            if (lowerName.find(lowerQuery) != std::string::npos)
                result.push_back(&pair.second);
        }

        return result;
    }

    size_t TotalCharacters() const { return Characters.size(); }

    void Clear()
    {
        Characters.clear();
        GenericCharacters.clear();
        InfoToNpcMap.clear();
    }

    void PrintStats() const
    {
        size_t males = 0, females = 0, unknown = 0, totalRefs = 0;

        for (const auto& pair : Characters)
        {
            switch (pair.second.Gender)
            {
            case CharacterGender::Male:    males++;   break;
            case CharacterGender::Female:  females++; break;
            default:                       unknown++; break;
            }
            totalRefs += pair.second.AssociatedRefs.size();
        }

        std::cout << "=== CharacterTracker Stats ===\n";
        std::cout << "Total NPCs:    " << Characters.size() << "\n";
        std::cout << "Male:          " << males << "\n";
        std::cout << "Female:        " << females << "\n";
        std::cout << "Unknown:       " << unknown << "\n";
        std::cout << "Total RefLinks:" << totalRefs << "\n";
        std::cout << "INFO mappings: " << InfoToNpcMap.size() << "\n";
    }
};