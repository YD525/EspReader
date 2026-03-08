#pragma once
#include "EspRecord.cpp"
#include "CharacterTrackerBuilder.cpp"

class CharacterTrackerBuilder
{
public:
    static void Build(const EspData& data, CharacterTracker& tracker)
    {
        tracker.Clear();

        BuildFromNpcRecords(data, tracker);

        BuildFromInfoRecords(data, tracker);
    }

private:

    static void BuildFromNpcRecords(const EspData& data, CharacterTracker& tracker)
    {
        for (const auto& rec : data.Records)
        {
            if (rec.Sig != "NPC_") continue;

            std::string name, voiceType;
            CharacterGender gender = CharacterGender::Unknown;

            for (const auto& sub : rec.SubRecords)
            {
                if (sub.Sig == "FULL")
                {
                    name = sub.GetString();
                }
            }

            std::string editorID = rec.EditorID;

            {
                std::string lower = editorID;
                std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
                if (lower.find("female") != std::string::npos)
                    gender = CharacterGender::Female;
                else if (lower.find("male") != std::string::npos)
                    gender = CharacterGender::Male;
            }

            auto& charRec = tracker.RegisterNpc(rec.FormID, name, editorID, voiceType, gender);

            RecordRef selfRef(rec.FormID, "NPC_", "FULL", name, rec.Index);
            charRec.AddRef(selfRef);
        }
    }


    static void BuildFromInfoRecords(const EspData& data, CharacterTracker& tracker)
    {
        for (const auto& rec : data.Records)
        {
            if (rec.Sig != "INFO") continue;

            std::string dialogText;
            uint32_t    speakerFormID = 0;  
            bool        foundAnam = false;

            for (const auto& sub : rec.SubRecords)
            {
                if (sub.Sig == "NAM1")
                {
                    dialogText = sub.GetString();
                }
                // ANAM: Speaker (Actor / ActorBase) FormID£¬4 bytes
                else if (sub.Sig == "ANAM" && sub.Data.size() >= 4)
                {
                    std::memcpy(&speakerFormID, sub.Data.data(), 4);
                    foundAnam = true;
                }
            }

            if (foundAnam && speakerFormID != 0)
            {
                tracker.LinkInfoToNpc(rec.FormID, speakerFormID, dialogText, rec.Index);

                if (tracker.Characters.find(speakerFormID) == tracker.Characters.end())
                {
                    tracker.RegisterNpc(speakerFormID, "", "", "");
                }
            }
            else
            {
                tracker.LinkInfoToNpc(rec.FormID, 0, dialogText, rec.Index);
            }
        }
    }
};