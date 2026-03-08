#pragma once
#include "EspRecord.cpp"
#include "CharacterTrackerBuilder.cpp"

class CharacterTrackerBuilder
{
public:
	static void Build(const EspData& data, CharacterTracker& tracker)
	{
		tracker.ClearAll();

		BuildFromNpcRecords(data, tracker);
	}

	static void BuildFromNpcRecords(const EspData& data, CharacterTracker& tracker)
	{
		for (const auto& Rec : data.Records)
		{
			if (Rec.Sig != "NPC_") continue;

			std::string Name;
			for (const auto& Sub : Rec.SubRecords)
				if (Sub.Sig == "FULL") Name = Sub.GetString();

			std::string EditorID = Rec.EditorID;

			CharacterGender Gender = Rec.HasPendingACBS
				? Rec.PendingGenderFromACBS
				: CharacterGender::Unknown;

			std::string voiceType = Rec.HasPendingVTCK
				? std::to_string(Rec.PendingVTCK)
				: "";

			auto& Character = tracker.RegisterNpc(Rec.FormID, Name, EditorID, voiceType, Gender);
		}
	}
};