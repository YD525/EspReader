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

			std::string name;
			for (const auto& sub : rec.SubRecords)
				if (sub.Sig == "FULL") name = sub.GetString();

			std::string editorID = rec.EditorID;

			CharacterGender gender = rec.HasPendingACBS
				? rec.PendingGenderFromACBS
				: CharacterGender::Unknown;

			std::string voiceType = rec.HasPendingVTCK
				? std::to_string(rec.PendingVTCK)
				: "";

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
			for (const auto& sub : rec.SubRecords)
				if (sub.Sig == "NAM1") dialogText = sub.GetString();

			if (rec.HasPendingANAM && rec.PendingANAM != 0)
			{
				tracker.LinkInfoToNpc(rec.FormID, rec.PendingANAM, dialogText, rec.Index);
				if (tracker.Characters.find(rec.PendingANAM) == tracker.Characters.end())
					tracker.RegisterNpc(rec.PendingANAM, "", "", "");
			}
			else
			{
				tracker.LinkInfoToNpc(rec.FormID, 0, dialogText, rec.Index);
			}
		}
	}
};