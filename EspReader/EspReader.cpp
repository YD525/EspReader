// EspReader.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <fstream>
#include <vector>
#include <string>
#include <iostream>
#include <cstdint>

#pragma pack(push, 1)
struct RecordHeader {
    char     sig[4];
    uint32_t dataSize;
    uint32_t flags;
    uint32_t formID;
    uint32_t versionCtrl;
    uint16_t version;
    uint16_t unknown;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct GroupHeader {
    char     sig[4];   // "GRUP"
    uint32_t size;
    char     label[4];
    uint32_t groupType;
    uint32_t stamp;
    uint32_t unknown;
};
#pragma pack(pop)

void ParseRecord(std::ifstream& f, const char sig[4]);

template<typename T>
inline void Read(std::ifstream& f, T& out)
{
    f.read(reinterpret_cast<char*>(&out), sizeof(T));
}

inline bool IsGRUP(const char sig[4])
{
    return std::memcmp(sig, "GRUP", 4) == 0;
}

void ParseGroup(std::ifstream& f) 
{
    GroupHeader gh;
    std::memcpy(gh.sig, "GRUP", 4);

    Read(f, gh.size);
    Read(f, gh.label);
    Read(f, gh.groupType);
    Read(f, gh.stamp);
    Read(f, gh.unknown);

    std::streampos groupStart = f.tellg();
    uint32_t bytesRead = 0;
    uint32_t contentSize = gh.size - 24;

    while (bytesRead < contentSize && f.good()) {
        std::streampos before = f.tellg();

        char sig[4];
        if (!f.read(sig, 4))
            break;

        if (IsGRUP(sig)) {
            ParseGroup(f);
        }
        else {
            ParseRecord(f, sig);
        }

        std::streampos after = f.tellg();
        bytesRead += uint32_t(after - before);
    }
}


void ParseRecord(std::ifstream& f, const char sig[4]) 
{
    RecordHeader hdr;
    std::memcpy(hdr.sig, sig, 4);

    Read(f, hdr.dataSize);
    Read(f, hdr.flags);
    Read(f, hdr.formID);
    Read(f, hdr.versionCtrl);
    Read(f, hdr.version);
    Read(f, hdr.unknown);

    std::string name(hdr.sig, 4);
    std::cout
        << "Record: " << name
        << " Size=" << hdr.dataSize
        << " FormID=0x" << std::hex << hdr.formID << std::dec
        << "\n";

    if (hdr.dataSize > 0) {
        f.seekg(hdr.dataSize, std::ios::cur);
    }
}

int main()
{
    const char* EspPath =
        "C:\\Users\\52508\\Desktop\\1TestMod\\Chatty NPCs-133266-1-5-1737407563\\Chatty NPCs.esp";

    std::ifstream f(EspPath, std::ios::binary);
    if (!f.is_open()) {
        std::cerr << "Failed to open esp file: " << EspPath << "\n";
        return 1;
    }

    std::cout << "Reading ESP: " << EspPath << "\n";

    while (f.good()) {
        char sig[4];

        if (!f.read(sig, 4))
            break;

        if (IsGRUP(sig)) {
            ParseGroup(f);
        }
        else {
            ParseRecord(f, sig);
        }
    }

    std::cout << "Finished reading ESP.\n";
    return 0;
}

