#include <fstream>
#include <vector>
#include <string>
#include <iostream>
#include <cstdint>
#include <stack>
#include <unordered_map>
#include <unordered_set>
#include "miniz.h"
#include "EspRecord.h"
#include <random>

#define NOMINMAX  
#define WIN32_LEAN_AND_MEAN 

#include <windows.h>

#ifdef SSELexApi_EXPORTS
#define SSELex_API __declspec(dllexport)
#else
#define SSELex_API __declspec(dllimport)
#endif


extern "C" 
{
	SSELex_API void C_Init();
	SSELex_API void C_InitDefaultFilter();
	SSELex_API int C_SetDefaultFilter();
	SSELex_API int C_SetFilter(const char* parentSig, const char** childSigs, int childCount);
	SSELex_API void C_ClearFilter();
	SSELex_API int C_ReadEsp(const wchar_t* EspPath);
	SSELex_API EspRecord** C_SearchBySig(const char* ParentSig, const char* ChildSig, int* OutCount);
	SSELex_API void FreeSearchResults(EspRecord** Arr, int Count);

	SSELex_API const char* C_GetRecordSig(EspRecord* record);
	SSELex_API uint32_t C_GetRecordFormID(EspRecord* record);
	SSELex_API uint32_t C_GetRecordFlags(EspRecord* record);
	SSELex_API int C_GetSubRecordCount(EspRecord* record);

	SSELex_API const SubRecordData* C_GetSubRecordData_Ptr(EspRecord* record, int index);
	SSELex_API int C_SubRecordData_GetOccurrenceIndex(const SubRecordData* subRecord);
	SSELex_API int C_SubRecordData_GetGlobalIndex(const SubRecordData* subRecord);
	SSELex_API const char* C_SubRecordData_GetSig(const SubRecordData* subRecord);
	SSELex_API const char* C_SubRecordData_GetString(const SubRecordData* subRecord);
	SSELex_API bool C_SubRecordData_IsLocalized(const SubRecordData* subRecord);
	SSELex_API uint32_t C_SubRecordData_GetStringID(const SubRecordData* subRecord);
	SSELex_API int C_SubRecordData_GetDataSize(const SubRecordData* subRecord);
	SSELex_API bool C_SubRecordData_GetData(const SubRecordData* subRecord, uint8_t* buffer, int bufferSize);
	SSELex_API int C_SubRecordData_GetStringUtf8(const SubRecordData* subRecord, uint8_t* buffer, int bufferSize);
	SSELex_API int C_SubRecordData_GetSigUtf8(const SubRecordData* subRecord, uint8_t* buffer, int bufferSize);

	SSELex_API void C_Clear();
	SSELex_API void C_Close();
}

const SubRecordData* C_GetSubRecordData_Ptr(EspRecord* record, int index)
{
	if (!record || index < 0 || index >= record->SubRecords.size())
		return nullptr;
	return &record->SubRecords[index];
}

int C_SubRecordData_GetStringUtf8(const SubRecordData* subRecord, uint8_t* buffer, int bufferSize)
{
	if (!subRecord) return -1;

	std::string str = subRecord->GetString();
	int len = static_cast<int>(str.size());

	if (buffer && bufferSize > len)
	{
		std::memcpy(buffer, str.c_str(), len);
		buffer[len] = 0;
	}

	return len;
}

int C_SubRecordData_GetSigUtf8(const SubRecordData* subRecord, uint8_t* buffer, int bufferSize)
{
	if (!subRecord) return -1;

	int len = static_cast<int>(subRecord->Sig.size());

	if (buffer && bufferSize > len)
	{
		std::memcpy(buffer, subRecord->Sig.c_str(), len);
		buffer[len] = 0;
	}

	return len;
}

int C_SubRecordData_GetOccurrenceIndex(const SubRecordData* subRecord)
{
	return subRecord ? subRecord->OccurrenceIndex : -1;
}

int C_SubRecordData_GetGlobalIndex(const SubRecordData* subRecord)
{
	return subRecord ? subRecord->GlobalIndex : -1;
}

const char* C_SubRecordData_GetSig(const SubRecordData* subRecord)
{
	if (!subRecord) return nullptr;
	return subRecord->Sig.c_str();
}

const char* C_SubRecordData_GetString(const SubRecordData* subRecord)
{
	if (!subRecord) return nullptr;
	static std::string buffer;
	buffer = subRecord->GetString();
	return buffer.c_str();
}

bool C_SubRecordData_IsLocalized(const SubRecordData* subRecord)
{
	return subRecord ? subRecord->IsLocalized : false;
}

uint32_t C_SubRecordData_GetStringID(const SubRecordData* subRecord)
{
	return subRecord ? subRecord->StringID : 0;
}

int C_SubRecordData_GetDataSize(const SubRecordData* subRecord)
{
	return subRecord ? static_cast<int>(subRecord->Data.size()) : 0;
}

bool C_SubRecordData_GetData(const SubRecordData* subRecord, uint8_t* buffer, int bufferSize)
{
	if (!subRecord || !buffer) return false;

	const auto& data = subRecord->Data;
	if (bufferSize < data.size())
		return false;

	std::memcpy(buffer, data.data(), data.size());
	return true;
}

const char* C_GetRecordSig(EspRecord* record)
{
	if (!record) return nullptr;
	return record->Sig.c_str();
}

uint32_t C_GetRecordFormID(EspRecord* record)
{
	if (!record) return 0;
	return record->FormID;
}

uint32_t C_GetRecordFlags(EspRecord* record)
{
	if (!record) return 0;
	return record->Flags;
}

int C_GetSubRecordCount(EspRecord* record)
{
	if (!record) return 0;
	return static_cast<int>(record->SubRecords.size());
}


void Close();

#pragma pack(push, 1)
struct RecordHeader
{
	char     Sig[4];//Offse 0 ~ 3
	uint32_t DataSize;// 4 ~ 7
	uint32_t Flags;// 8 ~ 11
	uint32_t FormID;// 12 ~ 15
	uint32_t VersionCtrl;// 16 ~ 19
	uint16_t Version;//20 ~ 21
	uint16_t Unknown;//22 ~ 23
};
#pragma pack(pop)

#pragma pack(push, 1)
struct GroupHeader
{
	char     Sig[4];   // "GRUP"
	uint32_t Size;
	char     Label[4];
	uint32_t GroupType;
	uint32_t Stamp;
	uint32_t Unknown;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct SubRecordHeader
{
	char Sig[4];
	uint16_t Size;
};
#pragma pack(pop)

constexpr uint32_t RECORD_FLAG_COMPRESSED = 0x00040000;


// Read helper
template<typename T>
inline void Read(std::ifstream& f, T& out) { f.read(reinterpret_cast<char*>(&out), sizeof(T)); }
inline bool IsGRUP(const char sig[4]) { return std::memcmp(sig, "GRUP", 4) == 0; }
bool IsCompressed(const RecordHeader& hdr) { return (hdr.Flags & RECORD_FLAG_COMPRESSED) != 0; }

// Decompress
bool ZlibDecompress(const uint8_t* src, size_t srcSize, std::vector<uint8_t>& out, size_t uncompressedSize)
{
	out.resize(uncompressedSize);
	size_t ret = tinfl_decompress_mem_to_mem(out.data(), uncompressedSize, src, srcSize, TINFL_FLAG_PARSE_ZLIB_HEADER);
	return ret == uncompressedSize;
}

//EnCompress
bool ZlibCompress(const uint8_t* src, size_t srcSize, std::vector<uint8_t>& out)
{
	mz_ulong destLen = compressBound(srcSize);
	out.resize(destLen);
	int ret = compress2(out.data(), &destLen, src, srcSize, Z_BEST_COMPRESSION);
	if (ret != Z_OK) return false;
	out.resize(destLen);
	return true;
}

RecordFilter* TranslateFilter;
StringsManager* g_StringsManager = nullptr;

// Parse subrecords from memory buffer with filter
void ParseSubRecords(const uint8_t* data, size_t dataSize, EspRecord& rec,
	const RecordFilter& filter, const char recordSig[4])
{
	size_t offset = 0;
	while (offset + sizeof(SubRecordHeader) <= dataSize)
	{
		const SubRecordHeader* sub = reinterpret_cast<const SubRecordHeader*>(data + offset);
		if (offset + sizeof(SubRecordHeader) + sub->Size > dataSize) break;

		rec.AddSubRecord(sub->Sig, data + offset + sizeof(SubRecordHeader), sub->Size,*TranslateFilter);

		offset += sizeof(SubRecordHeader) + sub->Size;
	}
}

// Parse subrecords from stream with filter
void ParseSubRecordsStream(std::ifstream& f, uint32_t recordSize, EspRecord& rec,
	const RecordFilter& filter, const char recordSig[4])
{
	uint32_t bytesRead = 0;
	while (bytesRead < recordSize && f.good())
	{
		if (bytesRead + sizeof(SubRecordHeader) > recordSize)
		{
			f.seekg(recordSize - bytesRead, std::ios::cur);
			break;
		}

		SubRecordHeader sub{};
		if (!f.read(reinterpret_cast<char*>(&sub), sizeof(sub))) break;
		bytesRead += sizeof(SubRecordHeader);

		if (bytesRead + sub.Size > recordSize)
		{
			f.seekg(recordSize - bytesRead, std::ios::cur);
			break;
		}

		std::vector<uint8_t> buf(sub.Size);
		if (sub.Size > 0)
		{
			f.read(reinterpret_cast<char*>(buf.data()), sub.Size);
			bytesRead += sub.Size;
		}

		rec.AddSubRecord(sub.Sig, buf.data(), sub.Size,*TranslateFilter);
	}
}

void ParseRecord(std::ifstream& f, const char Sig[4], EspData& doc, const RecordFilter& filter)
{
	RecordHeader hdr{};
	std::memcpy(hdr.Sig, Sig, 4);
	Read(f, hdr.DataSize);
	Read(f, hdr.Flags);
	Read(f, hdr.FormID);
	Read(f, hdr.VersionCtrl);
	Read(f, hdr.Version);
	Read(f, hdr.Unknown);

	EspRecord rec(hdr.Sig, hdr.FormID, hdr.Flags);

	if (IsCompressed(hdr))
	{
		if (hdr.DataSize < 4)
		{
			f.seekg(hdr.DataSize, std::ios::cur);
			doc.AddRecord(rec,*TranslateFilter);
			return;
		}

		uint32_t uncompressedSize = 0;
		Read(f, uncompressedSize);

		uint32_t compressedSize = hdr.DataSize - 4;
		std::vector<uint8_t> compressed(compressedSize);
		f.read(reinterpret_cast<char*>(compressed.data()), compressedSize);

		std::vector<uint8_t> decompressed;
		if (ZlibDecompress(compressed.data(), compressedSize, decompressed, uncompressedSize))
		{
			ParseSubRecords(decompressed.data(), decompressed.size(), rec, filter, hdr.Sig);
		}
	}
	else
	{
		ParseSubRecordsStream(f, hdr.DataSize, rec, filter, hdr.Sig);
	}

	doc.AddRecord(rec, *TranslateFilter);
}

void ParseCellGroup(std::ifstream& f, EspData& doc, const RecordFilter& filter, uint32_t groupSize)
{
	uint32_t bytesRead = 0;

	while (bytesRead < groupSize && f.good())
	{
		if (groupSize - bytesRead < 4)
		{
			f.seekg(groupSize - bytesRead, std::ios::cur);
			break;
		}

		char sig[4];
		std::streampos posBeforeRead = f.tellg();
		if (!f.read(sig, 4))
		{
			break;
		}
		bytesRead += 4;

		if (IsGRUP(sig))
		{
			if (groupSize - bytesRead < 20)
			{
				f.seekg(groupSize - bytesRead, std::ios::cur);
				break;
			}

			GroupHeader gh{};
			std::memcpy(gh.Sig, sig, 4);
			Read(f, gh.Size);           // +4 bytes
			f.read(gh.Label, 4);        // +4 bytes
			Read(f, gh.GroupType);      // +4 bytes
			Read(f, gh.Stamp);          // +4 bytes
			Read(f, gh.Unknown);        // +4 bytes
			bytesRead += 20;            // Total: 24 bytes for full GRUP header

			if (gh.Size < 24 || gh.Size >(groupSize - bytesRead + 24))
			{
				f.seekg(groupSize - bytesRead, std::ios::cur);
				break;
			}

			doc.IncrementGrupCount();

			// CELL GRUP
			// GroupType:
			// 0 = Top (World Children)
			// 1 = World Children
			// 2 = Interior Cell Block
			// 3 = Interior Cell Sub-Block
			// 4 = Exterior Cell Block
			// 5 = Exterior Cell Sub-Block
			// 6 = Cell Children (Persistent)
			// 7 = Cell Children (Temporary)
			// 8 = Cell Children (VWD)
			// 9 = Cell Children

			uint32_t contentSize = gh.Size - 24;
			ParseCellGroup(f, doc, filter, contentSize);
			bytesRead += contentSize;
		}
		else
		{
			if (groupSize - bytesRead < 20)
			{
				f.seekg(groupSize - bytesRead, std::ios::cur);
				break;
			}

			RecordHeader hdr{};
			std::memcpy(hdr.Sig, sig, 4);
			Read(f, hdr.DataSize);
			Read(f, hdr.Flags);
			Read(f, hdr.FormID);
			Read(f, hdr.VersionCtrl);
			Read(f, hdr.Version);
			Read(f, hdr.Unknown);
			bytesRead += 20;

			uint32_t recordTotalSize = hdr.DataSize;

			if (recordTotalSize > (groupSize - bytesRead))
			{
				f.seekg(groupSize - bytesRead, std::ios::cur);
				break;
			}

			EspRecord Record(hdr.Sig, hdr.FormID, hdr.Flags);

			if (IsCompressed(hdr))
			{
				if (hdr.DataSize < 4)
				{
					f.seekg(hdr.DataSize, std::ios::cur);
				}
				else
				{
					uint32_t uncompressedSize = 0;
					Read(f, uncompressedSize);

					uint32_t compressedSize = hdr.DataSize - 4;
					std::vector<uint8_t> compressed(compressedSize);
					f.read(reinterpret_cast<char*>(compressed.data()), compressedSize);

					std::vector<uint8_t> decompressed;
					if (ZlibDecompress(compressed.data(), compressedSize, decompressed, uncompressedSize))
					{
						ParseSubRecords(decompressed.data(), decompressed.size(), Record, filter, hdr.Sig);
					}
				}
			}
			else
			{
				ParseSubRecordsStream(f, hdr.DataSize, Record, filter, hdr.Sig);
			}

			if (Record.CanTranslate())
			{
				doc.AddRecord(Record,*TranslateFilter);
			}

			bytesRead += recordTotalSize;
		}

		std::streampos posAfterRead = f.tellg();
		int64_t actualConsumed = static_cast<int64_t>(posAfterRead - posBeforeRead);

		if (actualConsumed > 0)
		{
			bytesRead = static_cast<uint32_t>(posAfterRead - posBeforeRead + (bytesRead - actualConsumed));
		}
	}

	if (bytesRead < groupSize)
	{
		f.seekg(groupSize - bytesRead, std::ios::cur);
	}
}

// Iterative group parsing with filter
void ParseGroupIterative(std::ifstream& f, EspData& doc, const RecordFilter& filter)
{
	struct GroupState
	{
		uint32_t remaining;
	};
	std::stack<GroupState> groupStack;

	GroupHeader gh{};
	std::memcpy(gh.Sig, "GRUP", 4);
	Read(f, gh.Size);
	f.read(gh.Label, 4);
	Read(f, gh.GroupType);
	Read(f, gh.Stamp);
	Read(f, gh.Unknown);

	if (gh.Size < 24) return;

	std::string label(gh.Label, 4);
	std::cout << "Top-level GRUP: Label='" << label
		<< "' Type=" << gh.GroupType
		<< " Size=" << gh.Size << "\n";

	doc.IncrementGrupCount();

	if (std::memcmp(gh.Label, "CELL", 4) == 0)
	{
		std::cout << "  -> Entering CELL group parser\n";
		ParseCellGroup(f, doc, filter, gh.Size - 24);
		return;
	}

	groupStack.push({ gh.Size - 24 });

	while (!groupStack.empty())
	{
		auto& state = groupStack.top();

		if (state.remaining == 0)
		{
			groupStack.pop();
			continue;
		}

		if (state.remaining < 4)
		{
			f.seekg(state.remaining, std::ios::cur);
			groupStack.pop();
			continue;
		}

		char sig[4];
		if (!f.read(sig, 4))
		{
			groupStack.pop();
			continue;
		}

		if (IsGRUP(sig))
		{
			if (state.remaining < 24)
			{
				f.seekg(state.remaining - 4, std::ios::cur);
				groupStack.pop();
				continue;
			}

			Read(f, gh.Size);
			f.read(gh.Label, 4);
			Read(f, gh.GroupType);
			Read(f, gh.Stamp);
			Read(f, gh.Unknown);

			if (gh.Size < 24 || gh.Size > state.remaining)
			{
				groupStack.pop();
				continue;
			}

			if (std::memcmp(gh.Label, "CELL", 4) == 0)
			{
				std::cout << "    -> Nested CELL group, using ParseCellGroup\n";
				ParseCellGroup(f, doc, filter, gh.Size - 24);
				state.remaining -= gh.Size;
				continue;
			}

			doc.IncrementGrupCount();
			state.remaining -= gh.Size;
			groupStack.push({ gh.Size - 24 });
		}
		else
		{
			if (state.remaining < 24)
			{
				f.seekg(state.remaining - 4, std::ios::cur);
				groupStack.pop();
				continue;
			}

			RecordHeader hdr{};
			std::memcpy(hdr.Sig, sig, 4);
			Read(f, hdr.DataSize);
			Read(f, hdr.Flags);
			Read(f, hdr.FormID);
			Read(f, hdr.VersionCtrl);
			Read(f, hdr.Version);
			Read(f, hdr.Unknown);

			uint32_t recordTotalSize = 24 + hdr.DataSize;

			if (recordTotalSize > state.remaining)
			{
				groupStack.pop();
				continue;
			}

			EspRecord Record(hdr.Sig, hdr.FormID, hdr.Flags);

			if (IsCompressed(hdr))
			{
				if (hdr.DataSize < 4)
				{
					f.seekg(hdr.DataSize, std::ios::cur);
				}
				else
				{
					uint32_t uncompressedSize = 0;
					Read(f, uncompressedSize);

					uint32_t compressedSize = hdr.DataSize - 4;
					std::vector<uint8_t> compressed(compressedSize);
					f.read(reinterpret_cast<char*>(compressed.data()), compressedSize);

					std::vector<uint8_t> decompressed;
					if (ZlibDecompress(compressed.data(), compressedSize, decompressed, uncompressedSize))
					{
						ParseSubRecords(decompressed.data(), decompressed.size(), Record, filter, hdr.Sig);
					}
				}
			}
			else
			{
				ParseSubRecordsStream(f, hdr.DataSize, Record, filter, hdr.Sig);
			}

			if (Record.CanTranslate())
			{
				doc.AddRecord(Record,*TranslateFilter);
			}

			state.remaining -= recordTotalSize;
		}
	}
}

std::wstring LastSetPath;
EspData* Data;
void Clear();

int ReadEsp(const wchar_t* EspPath, const RecordFilter& Filter)
{
	Clear();
	LastSetPath = EspPath;
	Data = new EspData();

	std::ifstream F(EspPath, std::ios::binary);
	if (!F.is_open())
	{
		std::cerr << "Failed to open ESP: " << EspPath << "\n";
		return 1;
	}

	while (F.good() && F.peek() != EOF)
	{
		char Sig[4];
		if (!F.read(Sig, 4)) break;

		if (IsGRUP(Sig))
		{
			ParseGroupIterative(F, *Data, Filter);
		}
		else
		{
			ParseRecord(F, Sig, *Data, Filter);
		}
	}
	return 0;
}

int C_ReadEsp(const wchar_t* EspPath)
{
	return ReadEsp(EspPath, *TranslateFilter);
}

void C_InitDefaultFilter()
{
	if (TranslateFilter) delete TranslateFilter;
	TranslateFilter = new RecordFilter();
}

void C_ClearFilter()
{
	if (TranslateFilter)
	{
		TranslateFilter->CurrentConfig.clear();
	}
}

static std::string WStringToUtf8(const std::wstring& wstr)
{
	if (wstr.empty()) return std::string();
	int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.length(), NULL, 0, NULL, NULL);
	std::string result(size_needed, 0);
	WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.length(), &result[0], size_needed, NULL, NULL);
	return result;
}

int C_SetDefaultFilter()
{
	if (TranslateFilter)
	{
		std::unordered_map<std::string, std::vector<std::string>> Config =
		{
		   {"ACTI", {"FULL", "RNAM"}},
		   {"ALCH", {"FULL"}},
		   {"AMMO", {"FULL", "DESC"}},
		   {"APPA", {"FULL", "DESC"}},
		   {"ARMO", {"FULL", "DESC"}},
		   {"AVIF", {"FULL", "DESC"}},
		   {"BOOK", {"FULL", "DESC", "CNAM"}},
		   {"CLAS", {"FULL"}},
		   {"CELL", {"FULL"}},
		   {"CONT", {"FULL"}},
		   {"DIAL", {"FULL"}},
		   {"DOOR", {"FULL"}},
		   {"ENCH", {"FULL"}},
		   {"EXPL", {"FULL"}},
		   {"FLOR", {"FULL", "RNAM"}},
		   {"FURN", {"FULL"}},
		   {"HAZD", {"FULL"}},
		   {"INFO", {"NAM1", "RNAM"}},
		   {"INGR", {"FULL"}},
		   {"KEYM", {"FULL"}},
		   {"LCTN", {"FULL"}},
		   {"LIGH", {"FULL"}},
		   {"LSCR", {"DESC"}},
		   {"MESG", {"DESC", "FULL", "ITXT"}},
		   {"MGEF", {"FULL", "DNAM"}},
		   {"MISC", {"FULL"}},
		   {"NPC_", {"FULL", "SHRT"}},
		   {"NOTE", {"FULL", "TNAM"}},
		   {"PERK", {"FULL", "DESC", "EPF2", "EPFD"}},
		   {"PROJ", {"FULL"}},
		   {"QUST", {"FULL", "CNAM", "NNAM"}},
		   {"RACE", {"FULL", "DESC"}},
		   {"REFR", {"FULL"}},
		   {"REGN", {"RDMP"}},
		   {"SCRL", {"FULL", "DESC"}},
		   {"SHOU", {"FULL", "DESC"}},
		   {"SLGM", {"FULL"}},
		   {"SPEL", {"FULL", "DESC"}},
		   {"TACT", {"FULL"}},
		   {"TREE", {"FULL"}},
		   {"WEAP", {"DESC", "FULL"}},
		   {"WOOP", {"FULL", "TNAM"}},
		   {"WRLD", {"FULL"}},
		};

		TranslateFilter->LoadFromConfig(Config);

		return (int)TranslateFilter->CurrentConfig.size();
	}
	
	return -1;
}

 int C_SetFilter(const char* ParentSig,const char** ChildSigs,int ChildCount)
{
	 if (TranslateFilter)
	 {
		 std::string Parent(ParentSig);

		 std::vector<std::string>& Vec = TranslateFilter->CurrentConfig[Parent];

		 for (int i = 0; i < ChildCount; ++i)
		 {
			 Vec.push_back(std::string(ChildSigs[i]));
		 }

		 return Vec.size();
	 }
	 return -1;
}


void Init()
{
	g_StringsManager = new StringsManager();
}

void WaitForExit()
{
	std::cin.ignore(10000, '\n');
}


void GetCanTransCount()
{
	int GetTotal = Data->GetRecordsSubCount() + Data->GetCellRecordsSubCount();
	std::cout << "CanTransCount: " << GetTotal << "\n\n";
}


BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

void C_Init()
{
	Init();
}

void C_Close()
{
	Close();
}

EspRecord** C_SearchBySig(const char* ParentSig,const char* ChildSig,int* OutCount)
{
	std::vector<EspRecord> Matches = Data->SearchBySig(ParentSig, ChildSig);
	*OutCount = static_cast<int>(Matches.size());

	if (Matches.empty())
		return nullptr;

	EspRecord** Result = new EspRecord * [*OutCount];
	for (int i = 0; i < *OutCount; ++i)
	{
		Result[i] = new EspRecord(Matches[i]);
	}

	return Result;
}

void FreeSearchResults(EspRecord** Arr, int Count)
{
	if (!Arr) return;

	for (int i = 0; i < Count; ++i)
	{
		delete Arr[i];  
	}

	delete[] Arr; 
}

int main()
{
	SetConsoleOutputCP(CP_UTF8);

	Init();

	C_InitDefaultFilter();
	C_SetDefaultFilter();

	const wchar_t* EspPath = TEXT("C:\\Users\\52508\\Desktop\\1TestMod\\Interesting NPCs - 4.5 to 4.54 Update-29194-4-54-1681353795\\Data\\3DNPC.esp");

	std::cout << "Starting ESP parsing with filter...\n";
	if (TranslateFilter->IsEnabled())
	{
		std::cout << "Filter is enabled - only specified records will be parsed.\n";
	}
	else {
		std::cout << "Filter is disabled - all records will be parsed.\n";
	}

	int state = ReadEsp(EspPath, *TranslateFilter);

	if (state == 0)
	{
		std::cout << "Finished reading ESP.\n";
		std::cout << "Total records parsed: " << Data->GetTotalCount() << "\n";

		// Print statistics
		Data->PrintStatistics();

		//Test Query Cells
		std::cout << "CellCount: " << Data->SearchBySig("CELL").size() << "\n\n";

		GetCanTransCount();
	}
	else
	{
		std::cerr << "Failed to read ESP\n";
	}

	Close();

	WaitForExit();

	return 0;
}

const EspRecord* GetRecord(char* Key)
{
	if (!Key)
		return {};

	std::string UniqueKey(Key);

	auto Item = Data->FindByUniqueKey(UniqueKey);

	return Item;
}

void Clear()
{
	delete Data;
	Data = nullptr;

	LastSetPath = TEXT("");
}

void C_Clear()
{
	Clear();
}

void Close()
{
	delete TranslateFilter;
	TranslateFilter = nullptr;

	Clear();
}


#pragma region SaveFunc

std::vector<uint8_t> ModifySubRecords(
	const std::vector<uint8_t>& OriginalData,
	EspRecord* ModifiedRecord)
{
	std::vector<uint8_t> Result;
	size_t Offset = 0;

	std::unordered_map<std::string, std::unordered_map<int, const SubRecordData*>> ModifiedSubsMap;
	for (const auto& Sub : ModifiedRecord->SubRecords)
	{
		std::string Key = Sub.Sig;
		ModifiedSubsMap[Key][Sub.OccurrenceIndex] = &Sub;
	}

	std::unordered_map<std::string, int> CurrentOccurrence;

	while (Offset + sizeof(SubRecordHeader) <= OriginalData.size())
	{
		SubRecordHeader SH;
		std::memcpy(&SH, OriginalData.data() + Offset, sizeof(SH));

		if (Offset + sizeof(SubRecordHeader) + SH.Size > OriginalData.size())
		{
			std::cerr << "Warning: Corrupted subrecord data at offset " << Offset << "\n";
			break;
		}

		std::string SubSig(SH.Sig, 4);

		int Occurrence = CurrentOccurrence[SubSig]++;

		bool IsModified = false;
		const SubRecordData* ModifiedSub = nullptr;

		auto SigIt = ModifiedSubsMap.find(SubSig);
		if (SigIt != ModifiedSubsMap.end())
		{
			auto OccIt = SigIt->second.find(Occurrence);
			if (OccIt != SigIt->second.end())
			{
				ModifiedSub = OccIt->second;
				IsModified = true;
			}
		}

		if (IsModified && ModifiedSub)
		{
			if (ModifiedSub->Data.size() > 0xFFFF)
			{
				std::cerr << "Error: Subrecord " << SubSig << " size exceeds 65535 bytes\n";
				return {};
			}

			SubRecordHeader NewSH = SH;
			NewSH.Size = static_cast<uint16_t>(ModifiedSub->Data.size());

			Result.insert(Result.end(),
				reinterpret_cast<uint8_t*>(&NewSH),
				reinterpret_cast<uint8_t*>(&NewSH) + sizeof(NewSH));

			Result.insert(Result.end(),
				ModifiedSub->Data.begin(),
				ModifiedSub->Data.end());
		}
		else
		{
			Result.insert(Result.end(),
				OriginalData.begin() + Offset,
				OriginalData.begin() + Offset + sizeof(SubRecordHeader) + SH.Size);
		}

		Offset += sizeof(SubRecordHeader) + SH.Size;
	}

	return Result;
}

bool ProcessFileContent(std::ifstream& Fin, std::ofstream& Fout, int64_t RemainingSize);
bool ProcessGRUP(std::ifstream& Fin, std::ofstream& Fout, const char Sig[4]);
bool ProcessGRUPContent(std::ifstream& Fin, std::ofstream& Fout, int64_t ContentSize);
bool ProcessRecord(std::ifstream& Fin, std::ofstream& Fout, const char Sig[4]);

bool ProcessFileContent(std::ifstream& Fin, std::ofstream& Fout, int64_t RemainingSize)
{
	int64_t BytesProcessed = 0;

	while (Fin.good() && Fin.peek() != EOF)
	{
		if (RemainingSize >= 0 && BytesProcessed >= RemainingSize)
		{
			break;
		}

		char Sig[4];
		std::streampos PosBeforeSig = Fin.tellg();
		if (!Fin.read(Sig, 4)) break;

		if (IsGRUP(Sig))
		{
			if (!ProcessGRUP(Fin, Fout, Sig))
			{
				std::cerr << "Error: Failed to process GRUP at position " << PosBeforeSig << "\n";
				return false;
			}
		}
		else
		{
			if (!ProcessRecord(Fin, Fout, Sig))
			{
				std::cerr << "Error: Failed to process record at position " << PosBeforeSig << "\n";
				return false;
			}
		}

		std::streampos PosAfterProcess = Fin.tellg();
		int64_t Consumed = static_cast<int64_t>(PosAfterProcess) - static_cast<int64_t>(PosBeforeSig);
		BytesProcessed += Consumed;
	}

	return true;
}

bool ProcessGRUP(std::ifstream& Fin, std::ofstream& Fout, const char Sig[4])
{
	GroupHeader GH{};
	std::memcpy(GH.Sig, Sig, 4);

	Read(Fin, GH.Size);
	Fin.read(GH.Label, 4);
	Read(Fin, GH.GroupType);
	Read(Fin, GH.Stamp);
	Read(Fin, GH.Unknown);

	if (GH.Size < 24)
	{
		std::cerr << "Error: Invalid GRUP size: " << GH.Size << "\n";
		return false;
	}

	std::streampos GrupHeaderPos = Fout.tellp();
	Fout.write(reinterpret_cast<char*>(&GH), sizeof(GH));

	std::streampos GrupContentStart = Fout.tellp();

	int64_t ContentSize = GH.Size - 24;

	bool Success = ProcessGRUPContent(Fin, Fout, ContentSize);

	if (!Success)
	{
		return false;
	}

	std::streampos GrupContentEnd = Fout.tellp();
	uint32_t ActualContentSize = static_cast<uint32_t>(GrupContentEnd - GrupContentStart);
	uint32_t ActualGrupSize = ActualContentSize + 24;

	if (ActualGrupSize != GH.Size)
	{
		std::streampos SavedPos = Fout.tellp();
		Fout.seekp(GrupHeaderPos + std::streamoff(4));
		Fout.write(reinterpret_cast<char*>(&ActualGrupSize), sizeof(ActualGrupSize));
		Fout.seekp(SavedPos);
	}

	return true;
}

bool ProcessGRUPContent(std::ifstream& Fin, std::ofstream& Fout, int64_t ContentSize)
{
	std::streampos ContentStart = Fin.tellg();
	int64_t BytesProcessed = 0;

	while (BytesProcessed < ContentSize && Fin.good())
	{
		if (ContentSize - BytesProcessed < 4)
		{
			int64_t Remaining = ContentSize - BytesProcessed;
			Fin.seekg(Remaining, std::ios::cur);
			BytesProcessed += Remaining;
			break;
		}

		char Sig[4];
		std::streampos PosBeforeRead = Fin.tellg();
		if (!Fin.read(Sig, 4))
		{
			std::cerr << "Error: Failed to read signature in GRUP content\n";
			break;
		}

		if (IsGRUP(Sig))
		{
			if (!ProcessGRUP(Fin, Fout, Sig))
			{
				return false;
			}
		}
		else
		{
			if (!ProcessRecord(Fin, Fout, Sig))
			{
				return false;
			}
		}

		std::streampos PosAfterProcess = Fin.tellg();
		int64_t Consumed = static_cast<int64_t>(PosAfterProcess - PosBeforeRead);
		BytesProcessed += Consumed;
	}

	if (BytesProcessed < ContentSize)
	{
		int64_t Remaining = ContentSize - BytesProcessed;
		std::cerr << "Warning: Skipping " << Remaining << " unprocessed bytes in GRUP\n";
		Fin.seekg(Remaining, std::ios::cur);
	}
	else if (BytesProcessed > ContentSize)
	{
		int64_t Excess = BytesProcessed - ContentSize;
		std::cerr << "Warning: Consumed " << Excess << " extra bytes, rewinding\n";
		Fin.seekg(-Excess, std::ios::cur);
	}

	return true;
}

bool ProcessRecord(std::ifstream& Fin, std::ofstream& Fout, const char Sig[4])
{
	RecordHeader HDR{};
	std::memcpy(HDR.Sig, Sig, 4);

	Read(Fin, HDR.DataSize);
	Read(Fin, HDR.Flags);
	Read(Fin, HDR.FormID);
	Read(Fin, HDR.VersionCtrl);
	Read(Fin, HDR.Version);
	Read(Fin, HDR.Unknown);

	// Build lookup key
	std::string RecordKey(Sig, 4);
	RecordKey += ":" + std::to_string(HDR.FormID);

	// Search in main Records
	auto It = Data->RecordIndex.find(RecordKey);
	EspRecord* Rec = NULL;

	if (It != Data->RecordIndex.end())
	{
		Rec = &Data->Records[It->second];
	}
	else
	{
		// Search in CellRecords
		auto CellIt = Data->CellByFormID.find(HDR.FormID);
		if (CellIt != Data->CellByFormID.end() &&
			std::memcmp(Sig, "CELL", 4) == 0)
		{
			Rec = &Data->CellRecords[CellIt->second];
		}
	}

	if (Rec != NULL)
	{
		// Modified record
		std::vector<uint8_t> OriginalData(HDR.DataSize);
		Fin.read(reinterpret_cast<char*>(OriginalData.data()), HDR.DataSize);

		std::vector<uint8_t> WorkingData;
		bool WasCompressed = IsCompressed(HDR);

		if (WasCompressed)
		{
			uint32_t UncompressedSize;
			std::memcpy(&UncompressedSize, OriginalData.data(), 4);

			if (!ZlibDecompress(OriginalData.data() + 4,
				OriginalData.size() - 4,
				WorkingData,
				UncompressedSize))
			{
				std::cerr << "Error: Decompression failed for " << std::string(Sig, 4)
					<< " FormID 0x" << std::hex << HDR.FormID << std::dec << "\n";
				return false;
			}
		}
		else
		{
			WorkingData = OriginalData;
		}

		WorkingData = ModifySubRecords(WorkingData, Rec);

		std::vector<uint8_t> FinalData;
		if (WasCompressed)
		{
			std::vector<uint8_t> Compressed;
			if (!ZlibCompress(WorkingData.data(), WorkingData.size(), Compressed))
			{
				std::cerr << "Error: Compression failed for " << std::string(Sig, 4)
					<< " FormID 0x" << std::hex << HDR.FormID << std::dec << "\n";
				return false;
			}

			FinalData.resize(4 + Compressed.size());
			uint32_t UncompSize = static_cast<uint32_t>(WorkingData.size());
			std::memcpy(FinalData.data(), &UncompSize, 4);
			std::memcpy(FinalData.data() + 4, Compressed.data(), Compressed.size());
		}
		else
		{
			FinalData = WorkingData;
		}

		HDR.DataSize = static_cast<uint32_t>(FinalData.size());

		Fout.write(Sig, 4);
		Fout.write(reinterpret_cast<char*>(&HDR.DataSize), sizeof(HDR.DataSize));
		Fout.write(reinterpret_cast<char*>(&HDR.Flags), sizeof(HDR.Flags));
		Fout.write(reinterpret_cast<char*>(&HDR.FormID), sizeof(HDR.FormID));
		Fout.write(reinterpret_cast<char*>(&HDR.VersionCtrl), sizeof(HDR.VersionCtrl));
		Fout.write(reinterpret_cast<char*>(&HDR.Version), sizeof(HDR.Version));
		Fout.write(reinterpret_cast<char*>(&HDR.Unknown), sizeof(HDR.Unknown));
		Fout.write(reinterpret_cast<char*>(FinalData.data()), FinalData.size());
	}
	else
	{
		// Unmodified record - byte-perfect copy
		uint32_t TotalSize = 24 + HDR.DataSize;
		std::vector<uint8_t> CompleteRecord(TotalSize);

		std::memcpy(CompleteRecord.data(), Sig, 4);
		std::memcpy(CompleteRecord.data() + 4, &HDR.DataSize, sizeof(HDR.DataSize));
		std::memcpy(CompleteRecord.data() + 8, &HDR.Flags, sizeof(HDR.Flags));
		std::memcpy(CompleteRecord.data() + 12, &HDR.FormID, sizeof(HDR.FormID));
		std::memcpy(CompleteRecord.data() + 16, &HDR.VersionCtrl, sizeof(HDR.VersionCtrl));
		std::memcpy(CompleteRecord.data() + 20, &HDR.Version, sizeof(HDR.Version));
		std::memcpy(CompleteRecord.data() + 22, &HDR.Unknown, sizeof(HDR.Unknown));

		Fin.read(reinterpret_cast<char*>(CompleteRecord.data() + 24), HDR.DataSize);

		Fout.write(reinterpret_cast<char*>(CompleteRecord.data()), TotalSize);
	}

	return true;
}

bool SaveEsp(const char* SavePath)
{
	if (LastSetPath.empty())
	{
		//std::cerr << "Error: No source ESP file path set\n";
		return false;
	}

	std::ifstream Fin(LastSetPath, std::ios::binary);
	if (!Fin.is_open())
	{
		//std::cerr << "Error: Cannot open source ESP file: " << LastSetPath << "\n";
		return false;
	}

	std::ofstream Fout(SavePath, std::ios::binary);
	if (!Fout.is_open())
	{
		//std::cerr << "Error: Cannot create output ESP file: " << SavePath << "\n";
		Fin.close();
		return false;
	}

	//std::cout << "Processing: " << LastSetPath << " -> " << SavePath << "\n";

	bool Success = ProcessFileContent(Fin, Fout, -1);

	Fin.close();
	Fout.close();

	if (Success)
	{
		std::cout << "Successfully saved modified ESP to: " << SavePath << "\n";
	}
	else
	{
		std::cerr << "Failed to save ESP file\n";
	}

	return Success;
}

#pragma endregion