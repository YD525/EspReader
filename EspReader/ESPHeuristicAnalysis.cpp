#pragma once
#include <string>
#include <cstdint>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include "TextHelper.h"
#include <iomanip>
#include <sstream>

class ESP_HeuristicAnalysis
{
public:
    enum FieldType
    {
        PURE_STRING,        
        STRUCT_WITH_STRING, 
        BINARY_DATA,        
        MIXED_DATA,        
        UNKNOWN            
    };

    struct FieldInfo
    {
        std::string RecordSig;
        std::string SubSig;
        FieldType Type;
        size_t MinSize;
        size_t MaxSize;
        bool HasFixedSize;
        size_t FixedSize;

        size_t StringOffset;
        bool IsNullTerminated;
    };

    struct FieldStats
    {
        int TotalCount = 0;           
        int PassCount = 0;            
        int FailCount = 0;            
        double TotalQuality = 0.0;    
        double AvgQuality = 0.0;      
        int MinQuality = 100;         
        int MaxQuality = 0;           
        
        void AddScore(int quality, bool passed)
        {
            TotalCount++;
            if (passed)
                PassCount++;
            else
                FailCount++;
                
            TotalQuality += quality;
            AvgQuality = TotalQuality / TotalCount;
            
            if (quality < MinQuality)
                MinQuality = quality;
            if (quality > MaxQuality)
                MaxQuality = quality;
        }
        
        void Reset()
        {
            TotalCount = 0;
            PassCount = 0;
            FailCount = 0;
            TotalQuality = 0.0;
            AvgQuality = 0.0;
            MinQuality = 100;
            MaxQuality = 0;
        }
    };

private:
    std::unordered_map<std::string, FieldInfo> KnownFields_;
    
    std::unordered_map<std::string, FieldStats> FieldStatistics_;
    
    FieldStats GlobalStats_;

    std::string MakeKey(const std::string& RecordSig, const std::string& SubSig) const
    {
        return RecordSig + ":" + SubSig;
    }

public:
    ESP_HeuristicAnalysis()
    {
        InitializeKnownFields();
    }

    void InitializeKnownFields()
    {
        AddField("PERK", "EPF2", PURE_STRING, 0, 512, false, 0, 0, true);
        AddField("PERK", "EPFD", MIXED_DATA, 0, 512, false, 0, 0, true);

        AddField("MESG", "ITXT", MIXED_DATA, 0, 256, false, 0, 0, true);
        AddField("MESG", "DESC", PURE_STRING, 0, 4096, false, 0, 0, true);
        AddField("MESG", "FULL", PURE_STRING, 0, 256, false, 0, 0, true);

        AddField("INFO", "NAM1", PURE_STRING, 0, 4096, false, 0, 0, true);
        AddField("INFO", "RNAM", PURE_STRING, 0, 4096, false, 0, 0, true);

        AddField("QUST", "CNAM", PURE_STRING, 0, 4096, false, 0, 0, true);
        AddField("QUST", "NNAM", PURE_STRING, 0, 512, false, 0, 0, true);

        AddField("BOOK", "CNAM", PURE_STRING, 0, 65535, false, 0, 0, true);
        AddField("BOOK", "DESC", PURE_STRING, 0, 4096, false, 0, 0, true);

        AddField("REGN", "RDMP", MIXED_DATA, 0, 512, false, 0, 0, true);

        std::vector<std::string> RecordsWithFullName = {
            "ACTI", "ALCH", "AMMO", "APPA", "ARMO", "BOOK", "CLAS", "CELL",
            "CONT", "DOOR", "ENCH", "EXPL", "FLOR", "FURN", "HAZD", "INGR",
            "KEYM", "LCTN", "LIGH", "MGEF", "MISC", "NPC_", "PROJ", "RACE",
            "REFR", "SCRL", "SHOU", "SLGM", "SPEL", "TACT", "TREE", "WEAP",
            "WOOP", "WRLD"
        };

        for (const auto& sig : RecordsWithFullName)
        {
            AddField(sig, "FULL", PURE_STRING, 0, 256, false, 0, 0, true);
        }

        std::vector<std::string> RecordsWithDesc = {
            "AMMO", "APPA", "ARMO", "AVIF", "BOOK", "LSCR", "MGEF",
            "PERK", "RACE", "SCRL", "SHOU", "SPEL", "WEAP"
        };

        for (const auto& sig : RecordsWithDesc)
        {
            AddField(sig, "DESC", PURE_STRING, 0, 4096, false, 0, 0, true);
        }
    }

    void AddField(const std::string& RecordSig, const std::string& SubSig,
        FieldType Type, size_t MinSize, size_t MaxSize,
        bool HasFixedSize, size_t FixedSize,
        size_t StringOffset, bool IsNullTerminated)
    {
        FieldInfo Info;
        Info.RecordSig = RecordSig;
        Info.SubSig = SubSig;
        Info.Type = Type;
        Info.MinSize = MinSize;
        Info.MaxSize = MaxSize;
        Info.HasFixedSize = HasFixedSize;
        Info.FixedSize = FixedSize;
        Info.StringOffset = StringOffset;
        Info.IsNullTerminated = IsNullTerminated;

        KnownFields_[MakeKey(RecordSig, SubSig)] = Info;
    }

    const FieldInfo* GetFieldInfo(const std::string& RecordSig, const std::string& SubSig) const
    {
        std::string Key = MakeKey(RecordSig, SubSig);
        auto It = KnownFields_.find(Key);
        if (It != KnownFields_.end())
        {
            return &It->second;
        }
        return nullptr;
    }

    bool LooksLikeHexID(const uint8_t* Data, size_t Size) const
    {
        if (Size < 11) return false;

        size_t HexCount = 0;
        size_t DashCount = 0;

        for (size_t i = 0; i < Size && Data[i] != 0; ++i)
        {
            char C = static_cast<char>(Data[i]);
            if ((C >= '0' && C <= '9') || (C >= 'A' && C <= 'F') || (C >= 'a' && C <= 'f'))
            {
                HexCount++;
            }
            else if (C == '-')
            {
                DashCount++;
            }
        }

        size_t TotalRelevant = HexCount + DashCount;
        if (TotalRelevant > Size * 0.8 && DashCount >= 3)
        {
            return true;
        }

        return false;
    }

    bool IsNumericOnly(const uint8_t* Data, size_t Size) const
    {
        if (Size == 0) return false;

        size_t DigitCount = 0;
        size_t DecimalCount = 0;

        for (size_t i = 0; i < Size && Data[i] != 0; ++i)
        {
            char C = static_cast<char>(Data[i]);
            if (C >= '0' && C <= '9')
            {
                DigitCount++;
            }
            else if (C == '.' || C == ',')
            {
                DecimalCount++;
            }
            else if (C != ' ' && C != '\t' && C != '\r' && C != '\n')
            {
                return false;
            }
        }

        return DigitCount > 0 && (DigitCount + DecimalCount) * 10 > Size * 9;
    }

    bool ContainsHTMLTags(const uint8_t* Data, size_t Size) const
    {
        std::string Text(reinterpret_cast<const char*>(Data), Size);
        return Text.find('<') != std::string::npos && Text.find('>') != std::string::npos;
    }

    int CalculateTextQuality(const uint8_t* Data, size_t Size) const
    {
        if (Size == 0) return 0;
        int Score = 50;

        size_t PrintableCount = 0;
        size_t LetterCount = 0;
        size_t SpaceCount = 0;
        size_t PunctuationCount = 0;
        size_t ControlCount = 0;
        size_t ValidUTF8Sequences = 0;
        size_t TotalChars = 0;  

        size_t i = 0;
        while (i < Size && Data[i] != 0)
        {
            uint8_t C = Data[i];

            if (C <= 0x7F)
            {
                TotalChars++;  
                if (C >= 0x20)
                {
                    PrintableCount++;
                    if ((C >= 'A' && C <= 'Z') || (C >= 'a' && C <= 'z'))
                    {
                        LetterCount++;
                    }
                    else if (C == ' ' || C == '\t')
                    {
                        SpaceCount++;
                    }
                    else if ((C >= 0x21 && C <= 0x2F) || (C >= 0x3A && C <= 0x40) ||
                        (C >= 0x5B && C <= 0x60) || (C >= 0x7B && C <= 0x7E))
                    {
                        PunctuationCount++;
                    }
                }
                else if (C < 0x20)
                {
                    if (C != '\n' && C != '\r' && C != '\t')
                    {
                        ControlCount++;
                    }
                }
                i++;
            }
            else if ((C & 0xE0) == 0xC0)  
            {
                if (i + 1 < Size && (Data[i + 1] & 0xC0) == 0x80)
                {
                    TotalChars++;  
                    ValidUTF8Sequences++;
                    PrintableCount++;
                    LetterCount++;
                    i += 2;
                }
                else
                {
                    ControlCount++;
                    i++;
                }
            }
            else if ((C & 0xF0) == 0xE0)  
            {
                if (i + 2 < Size &&
                    (Data[i + 1] & 0xC0) == 0x80 &&
                    (Data[i + 2] & 0xC0) == 0x80)
                {
                    TotalChars++;  
                    ValidUTF8Sequences++;
                    PrintableCount++;
                    LetterCount++;
                    i += 3;
                }
                else
                {
                    ControlCount++;
                    i++;
                }
            }
            else if ((C & 0xF8) == 0xF0)  
            {
                if (i + 3 < Size &&
                    (Data[i + 1] & 0xC0) == 0x80 &&
                    (Data[i + 2] & 0xC0) == 0x80 &&
                    (Data[i + 3] & 0xC0) == 0x80)
                {
                    TotalChars++;  
                    ValidUTF8Sequences++;
                    PrintableCount++;
                    LetterCount++;
                    i += 4;
                }
                else
                {
                    ControlCount++;
                    i++;
                }
            }
            else
            {
                ControlCount++;
                i++;
            }
        }

        size_t TotalBytes = i;
        if (TotalChars == 0) return 0;

        float PrintableRatio = static_cast<float>(PrintableCount) / TotalChars;  
        float LetterRatio = static_cast<float>(LetterCount) / TotalChars;
        float ControlRatio = static_cast<float>(ControlCount) / TotalBytes;

        if (PrintableRatio > 0.8f) Score += 20;
        else if (PrintableRatio > 0.6f) Score += 10;

        if (LetterRatio > 0.3f) Score += 20;
        else if (LetterRatio > 0.1f) Score += 10;

        if (SpaceCount > 0 && TotalBytes > 10) Score += 10;
        if (ValidUTF8Sequences > 0) Score += 15;

        if (ControlRatio > 0.1f) Score -= 30;
        if (PrintableRatio < 0.5f) Score -= 20;
        if (LetterRatio < 0.05f && ValidUTF8Sequences == 0) Score -= 20;
        if (TotalBytes < 3) Score -= 20;

        return std::max(0, std::min(100, Score));
    }

    bool IsValidTranslatableText(const std::string& RecordSig,
        const std::string& SubSig,
        const uint8_t* Data,
        size_t Size,
        uint8_t LastEPFT = 0) const
    {
        if (!Data || Size == 0) return false;

        int Quality = CalculateTextQuality(Data, Size);

        const FieldInfo* Info = GetFieldInfo(RecordSig, SubSig);

        bool Passed = true;

        if (Info)
        {
            if (Info->HasFixedSize && Size != Info->FixedSize)
            {
                Passed = false;
            }

            if (Size < Info->MinSize || (Info->MaxSize > 0 && Size > Info->MaxSize))
            {
                Passed = false;
            }

            if (Info->Type == BINARY_DATA)
            {
                Passed = false;
            }
            else 
            if (Info->Type == MIXED_DATA)
            {
                if (RecordSig == "PERK" && SubSig == "EPFD")
                {
                    if (LastEPFT != 6 && LastEPFT != 7)
                    {
                        Passed = false;
                    }
                }

                if (RecordSig == "MESG" && SubSig == "ITXT")
                {
                    if (IsNumericOnly(Data, Size) || LooksLikeHexID(Data, Size))
                    {
                        Passed = false;
                    }
                }
            }
        }

        if (Quality < 40)
        {
            Passed = false;
        }

        if (LooksLikeHexID(Data, Size))
        {
            Passed = false;
        }

        std::string Text(reinterpret_cast<const char*>(Data), Size);
        Text.erase(std::remove(Text.begin(), Text.end(), '\0'), Text.end());

        if (RecordSig == "INFO" && SubSig == "NAM1")
        {
            if (!Text.empty() && Text.front() == '{' && Text.back() == '}')
            {
                Passed = false;
            }
        }

        if (Text.empty())
        {
            Passed = false;
        }

        if (Passed && !HasVisibleText(Text))
        {
            Passed = false;
        }

        const_cast<ESP_HeuristicAnalysis*>(this)->RecordStatistics(RecordSig, SubSig, Quality, Passed);

        return Passed;
    }

    void RecordStatistics(const std::string& RecordSig, const std::string& SubSig, int Quality, bool Passed)
    {
        std::string Key = MakeKey(RecordSig, SubSig);
        FieldStatistics_[Key].AddScore(Quality, Passed);
        GlobalStats_.AddScore(Quality, Passed);
    }

    void ResetStatistics()
    {
        FieldStatistics_.clear();
        GlobalStats_.Reset();
    }

    const FieldStats* GetFieldStatistics(const std::string& RecordSig, const std::string& SubSig) const
    {
        std::string Key = MakeKey(RecordSig, SubSig);
        auto It = FieldStatistics_.find(Key);
        if (It != FieldStatistics_.end())
        {
            return &It->second;
        }
        return nullptr;
    }

    const FieldStats& GetGlobalStatistics() const
    {
        return GlobalStats_;
    }

    std::string ExportFieldReport() const
    {
        std::stringstream ss;
        ss << std::fixed << std::setprecision(2);

        ss << "=== Scoring based on known configuration ===\n\n";

        if (GlobalStats_.TotalCount > 0)
        {
            ss << "=== Global Statistics ===\n";
            ss << "Total Fields Processed: " << GlobalStats_.TotalCount << "\n";
            ss << "Passed: " << GlobalStats_.PassCount 
               << " (" << (100.0 * GlobalStats_.PassCount / GlobalStats_.TotalCount) << "%)\n";
            ss << "Rejection: " << GlobalStats_.FailCount 
               << " (" << (100.0 * GlobalStats_.FailCount / GlobalStats_.TotalCount) << "%)\n";
            ss << "Average Quality Score: " << GlobalStats_.AvgQuality << "/100\n";
            ss << "Quality Range: " << GlobalStats_.MinQuality 
               << " - " << GlobalStats_.MaxQuality << "\n\n";
        }

        std::unordered_map<std::string, std::vector<std::string>> ByRecord;

        for (const auto& Pair : KnownFields_)
        {
            const FieldInfo& Info = Pair.second;
            ByRecord[Info.RecordSig].push_back(Info.SubSig);
        }

        for (const auto& Pair : ByRecord)
        {
            ss << Pair.first << ":\n";
            
            for (const auto& Sub : Pair.second)
            {
                const FieldInfo* Info = GetFieldInfo(Pair.first, Sub);
                ss << "  " << Sub << " - ";

                switch (Info->Type)
                {
                case PURE_STRING: ss << "PURE_STRING"; break;
                case STRUCT_WITH_STRING: ss << "STRUCT_WITH_STRING"; break;
                case BINARY_DATA: ss << "BINARY_DATA"; break;
                case MIXED_DATA: ss << "MIXED_DATA"; break;
                default: ss << "UNKNOWN"; break;
                }

                const FieldStats* Stats = GetFieldStatistics(Pair.first, Sub);
                if (Stats && Stats->TotalCount > 0)
                {
                    ss << " | Samples: " << Stats->TotalCount;
                    ss << " | Pass: " << Stats->PassCount << "/" << Stats->TotalCount;
                    ss << " (" << (100.0 * Stats->PassCount / Stats->TotalCount) << "%)";
                    ss << " | Avg Score: " << Stats->AvgQuality << "/100";
                    ss << " | Range: [" << Stats->MinQuality << "-" << Stats->MaxQuality << "]";
                }

                ss << "\n";
            }
            ss << "\n";
        }

        return ss.str();
    }
};