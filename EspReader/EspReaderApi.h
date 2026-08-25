#ifndef ESP_READER_API_H
#define ESP_READER_API_H

#include <stdint.h>
#include <wchar.h>

#if defined(_WIN32)
#if defined(ESP_READER_EXPORTS)
#define ESP_READER_API __declspec(dllexport)
#else
#define ESP_READER_API __declspec(dllimport)
#endif
#define ESP_READER_CALL __cdecl
#define ESP_READER_DIALOG_CALL __stdcall
#else
#define ESP_READER_API
#define ESP_READER_CALL
#define ESP_READER_DIALOG_CALL
#endif

#if defined(__cplusplus)
#define ESP_READER_NOEXCEPT noexcept
class EspInstance;
class EspRecord;
struct SubRecordData;
extern "C" {
#else
#define ESP_READER_NOEXCEPT
typedef struct EspInstance EspInstance;
typedef struct EspRecord EspRecord;
typedef struct SubRecordData SubRecordData;
#endif

/*
 * This value identifies the additive contract described by this header. It is
 * independent from the product version returned by C_GetVersion.
 */
#define ESP_READER_ABI_VERSION 1u

/* Boolean values cross the ABI as one unsigned byte. */
typedef uint8_t EspReaderBool;

/* Status values cross the ABI as signed 32-bit integers. */
typedef int32_t EspReaderStatus;
enum
{
    ESP_READER_STATUS_OK = 0,
    ESP_READER_STATUS_INVALID_ARGUMENT = 1,
    ESP_READER_STATUS_OUT_OF_RANGE = 2,
    ESP_READER_STATUS_BUFFER_TOO_SMALL = 3,
    ESP_READER_STATUS_IO_ERROR = 4,
    ESP_READER_STATUS_PARSE_ERROR = 5,
    ESP_READER_STATUS_OUT_OF_MEMORY = 6,
    ESP_READER_STATUS_INTERNAL_ERROR = 7
};

/*
 * Dialogue structures use the Windows default packing boundary explicitly.
 * C_LinkDIAL is 40 bytes on 64-bit Windows and 28 bytes on 32-bit Windows.
 */
#pragma pack(push, 8)
typedef struct C_DialResponseNode
{
    uint32_t ResponseID;
    uint32_t EmotionType;
    int32_t RecordOffset;
    int32_t SubOffset;
} C_DialResponseNode;

typedef struct C_LinkDIAL
{
    int32_t HasData;
    C_DialResponseNode Head;
    C_DialResponseNode* Links;
    uint32_t LinkCount;
} C_LinkDIAL;
#pragma pack(pop)

/*
 * All functions other than the three dialogue-context functions use cdecl.
 * Input char strings are UTF-8 unless documented as four-byte ASCII
 * signatures. C_ReadEsp accepts a null-terminated Windows UTF-16 path.
 * Buffer lengths are byte capacities, including space for a trailing null
 * byte where the function returns text. Text length results exclude that null.
 *
 * Handles are created by C_CreateInstance and must be destroyed exactly once
 * by C_DestroyInstance in this module. EspRecord and SubRecordData pointers are
 * borrowed. Search arrays and their records are owned by this module and must
 * be passed to FreeSearchResults with the returned count. Dialogue Links arrays
 * are owned by this module and must be released through C_FreeDialContext.
 * Returned const char pointers are borrowed and must never be freed.
 *
 * Handle, record, subrecord, input path, and required signature pointers must
 * be non-null. C_DestroyInstance, FreeSearchResults, and C_FreeDialContext
 * accept null as a no-op. Search childSig and modification newUtf8Data are
 * optional. C_SetFilter requires childSigs when childCount is positive and
 * requires every array element to be non-null. Search outCount is required.
 * Text output buffers may be null with a zero capacity to query the required
 * payload length; C_SubRecordData_GetData always requires a writable buffer.
 * A non-null text buffer must have capacity greater than the returned payload
 * length so the function can append its null byte.
 *
 * Every ABI entry point catches C++ exceptions. Status and error text are
 * thread-local and describe the most recent non-query call on the calling
 * thread. Error text remains valid until the next non-query call on that thread.
 */

ESP_READER_API uint32_t ESP_READER_CALL C_GetAbiVersion(void) ESP_READER_NOEXCEPT;
ESP_READER_API EspReaderStatus ESP_READER_CALL C_GetLastStatus(void) ESP_READER_NOEXCEPT;
ESP_READER_API int32_t ESP_READER_CALL C_GetLastErrorUtf8(
    uint8_t* buffer,
    int32_t bufferSize) ESP_READER_NOEXCEPT;

ESP_READER_API EspInstance* ESP_READER_CALL C_CreateInstance(void) ESP_READER_NOEXCEPT;
ESP_READER_API void ESP_READER_CALL C_DestroyInstance(EspInstance* handle) ESP_READER_NOEXCEPT;

ESP_READER_API const char* ESP_READER_CALL C_GetVersion(void) ESP_READER_NOEXCEPT;
ESP_READER_API int32_t ESP_READER_CALL C_GetVersionLength(void) ESP_READER_NOEXCEPT;

ESP_READER_API void ESP_READER_CALL C_InitFilter(EspInstance* handle) ESP_READER_NOEXCEPT;
ESP_READER_API int32_t ESP_READER_CALL C_SetSkyrimFilter(EspInstance* handle) ESP_READER_NOEXCEPT;
ESP_READER_API int32_t ESP_READER_CALL C_GetFilter(
    EspInstance* handle,
    uint8_t* buffer,
    int32_t bufferSize) ESP_READER_NOEXCEPT;
ESP_READER_API int32_t ESP_READER_CALL C_SetFilter(
    EspInstance* handle,
    const char* parentSig,
    const char** childSigs,
    int32_t childCount) ESP_READER_NOEXCEPT;
ESP_READER_API void ESP_READER_CALL C_ClearFilter(EspInstance* handle) ESP_READER_NOEXCEPT;

ESP_READER_API int32_t ESP_READER_CALL C_ReadEsp(
    EspInstance* handle,
    const wchar_t* espPath) ESP_READER_NOEXCEPT;
ESP_READER_API int32_t ESP_READER_CALL C_SaveEsp(
    EspInstance* handle,
    const char* utf8Path) ESP_READER_NOEXCEPT;
ESP_READER_API void ESP_READER_CALL C_Clear(EspInstance* handle) ESP_READER_NOEXCEPT;

ESP_READER_API const char* ESP_READER_CALL C_GetFieldReport(EspInstance* handle) ESP_READER_NOEXCEPT;
ESP_READER_API int32_t ESP_READER_CALL C_GetFieldReportLength(EspInstance* handle) ESP_READER_NOEXCEPT;

ESP_READER_API EspRecord** ESP_READER_CALL C_SearchBySig(
    EspInstance* handle,
    const char* parentSig,
    const char* childSig,
    int32_t* outCount) ESP_READER_NOEXCEPT;
ESP_READER_API void ESP_READER_CALL FreeSearchResults(
    EspRecord** records,
    int32_t count) ESP_READER_NOEXCEPT;

ESP_READER_API int32_t ESP_READER_CALL C_GetRecordSig(
    EspRecord* record,
    uint8_t* buffer,
    int32_t bufferSize) ESP_READER_NOEXCEPT;
ESP_READER_API uint32_t ESP_READER_CALL C_GetRecordFormID(EspRecord* record) ESP_READER_NOEXCEPT;
ESP_READER_API const char* ESP_READER_CALL C_GetRecordEditorID(EspRecord* record) ESP_READER_NOEXCEPT;
ESP_READER_API uint32_t ESP_READER_CALL C_GetRecordFlags(EspRecord* record) ESP_READER_NOEXCEPT;
ESP_READER_API int32_t ESP_READER_CALL C_GetRecordIndex(EspRecord* record) ESP_READER_NOEXCEPT;
ESP_READER_API int32_t ESP_READER_CALL C_GetSubRecordCount(EspRecord* record) ESP_READER_NOEXCEPT;

ESP_READER_API const SubRecordData* ESP_READER_CALL C_GetSubRecordData_Ptr(
    EspRecord* record,
    int32_t index) ESP_READER_NOEXCEPT;
ESP_READER_API int32_t ESP_READER_CALL C_SubRecordData_GetOccurrenceIndex(
    const SubRecordData* subRecord) ESP_READER_NOEXCEPT;
ESP_READER_API int32_t ESP_READER_CALL C_SubRecordData_GetIndex(
    const SubRecordData* subRecord) ESP_READER_NOEXCEPT;
ESP_READER_API const char* ESP_READER_CALL C_SubRecordData_GetSig(
    const SubRecordData* subRecord) ESP_READER_NOEXCEPT;
ESP_READER_API const char* ESP_READER_CALL C_SubRecordData_GetString(
    const SubRecordData* subRecord) ESP_READER_NOEXCEPT;
ESP_READER_API EspReaderBool ESP_READER_CALL C_SubRecordData_IsLocalized(
    const SubRecordData* subRecord) ESP_READER_NOEXCEPT;
ESP_READER_API uint32_t ESP_READER_CALL C_SubRecordData_GetStringID(
    const SubRecordData* subRecord) ESP_READER_NOEXCEPT;
ESP_READER_API int32_t ESP_READER_CALL C_SubRecordData_GetDataSize(
    const SubRecordData* subRecord) ESP_READER_NOEXCEPT;
ESP_READER_API EspReaderBool ESP_READER_CALL C_SubRecordData_GetData(
    const SubRecordData* subRecord,
    uint8_t* buffer,
    int32_t bufferSize) ESP_READER_NOEXCEPT;
ESP_READER_API int32_t ESP_READER_CALL C_SubRecordData_GetStringUtf8(
    const SubRecordData* subRecord,
    uint8_t* buffer,
    int32_t bufferSize) ESP_READER_NOEXCEPT;
ESP_READER_API int32_t ESP_READER_CALL C_SubRecordData_GetSigUtf8(
    const SubRecordData* subRecord,
    uint8_t* buffer,
    int32_t bufferSize) ESP_READER_NOEXCEPT;

ESP_READER_API int32_t ESP_READER_CALL C_ModifySubRecordByOffset(
    EspInstance* handle,
    int32_t isCell,
    int32_t recordOffset,
    int32_t subOffset,
    const char* newUtf8Data) ESP_READER_NOEXCEPT;
ESP_READER_API int32_t ESP_READER_CALL C_ModifySubRecord(
    EspInstance* handle,
    uint32_t formId,
    const char* recordSig,
    const char* subSig,
    int32_t occurrenceIndex,
    int32_t globalIndex,
    const char* newUtf8Data) ESP_READER_NOEXCEPT;

ESP_READER_API void ESP_READER_CALL C_ClearCharacterTracker(EspInstance* handle) ESP_READER_NOEXCEPT;
ESP_READER_API int32_t ESP_READER_CALL C_GetCharacterCount(EspInstance* handle) ESP_READER_NOEXCEPT;
ESP_READER_API uint32_t ESP_READER_CALL C_GetCharacterFormID(
    EspInstance* handle,
    int32_t index) ESP_READER_NOEXCEPT;
ESP_READER_API int32_t ESP_READER_CALL C_GetCharacterName(
    EspInstance* handle,
    int32_t index,
    uint8_t* buffer,
    int32_t bufferSize) ESP_READER_NOEXCEPT;
ESP_READER_API int32_t ESP_READER_CALL C_GetCharacterEditorID(
    EspInstance* handle,
    int32_t index,
    uint8_t* buffer,
    int32_t bufferSize) ESP_READER_NOEXCEPT;
ESP_READER_API int32_t ESP_READER_CALL C_GetCharacterVoiceType(
    EspInstance* handle,
    int32_t index,
    uint8_t* buffer,
    int32_t bufferSize) ESP_READER_NOEXCEPT;
ESP_READER_API int32_t ESP_READER_CALL C_GetCharacterGender(
    EspInstance* handle,
    int32_t index) ESP_READER_NOEXCEPT;
ESP_READER_API int32_t ESP_READER_CALL C_GetCharacterLinkedInfoCount(
    EspInstance* handle,
    int32_t index) ESP_READER_NOEXCEPT;
ESP_READER_API uint32_t ESP_READER_CALL C_GetCharacterLinkedInfo(
    EspInstance* handle,
    int32_t index,
    int32_t linkIndex) ESP_READER_NOEXCEPT;
ESP_READER_API int32_t ESP_READER_CALL C_GetCharacterLinkedFactionCount(
    EspInstance* handle,
    int32_t index) ESP_READER_NOEXCEPT;
ESP_READER_API uint32_t ESP_READER_CALL C_GetCharacterLinkedFaction(
    EspInstance* handle,
    int32_t index,
    int32_t linkIndex) ESP_READER_NOEXCEPT;
ESP_READER_API int32_t ESP_READER_CALL C_GetCharacterLinkedRaceCount(
    EspInstance* handle,
    int32_t index) ESP_READER_NOEXCEPT;
ESP_READER_API uint32_t ESP_READER_CALL C_GetCharacterLinkedRace(
    EspInstance* handle,
    int32_t index,
    int32_t linkIndex) ESP_READER_NOEXCEPT;
ESP_READER_API int32_t ESP_READER_CALL C_GetCharacterLinkedVoiceTypeCount(
    EspInstance* handle,
    int32_t index) ESP_READER_NOEXCEPT;
ESP_READER_API uint32_t ESP_READER_CALL C_GetCharacterLinkedVoiceType(
    EspInstance* handle,
    int32_t index,
    int32_t linkIndex) ESP_READER_NOEXCEPT;

ESP_READER_API C_LinkDIAL ESP_READER_DIALOG_CALL C_GetDialContext(
    EspInstance* handle,
    int32_t recordOffset,
    int32_t subOffset) ESP_READER_NOEXCEPT;
ESP_READER_API C_LinkDIAL ESP_READER_DIALOG_CALL C_GetDialContextByDial(
    EspInstance* handle,
    int32_t recordOffset) ESP_READER_NOEXCEPT;
ESP_READER_API void ESP_READER_DIALOG_CALL C_FreeDialContext(
    C_LinkDIAL* context) ESP_READER_NOEXCEPT;

ESP_READER_API int32_t ESP_READER_CALL C_GetTitleIndexByBookDesc(
    EspInstance* handle,
    int32_t recordOffset,
    int32_t descSubOffset) ESP_READER_NOEXCEPT;
ESP_READER_API int32_t ESP_READER_CALL C_GetDescIndexByBookTitle(
    EspInstance* handle,
    int32_t recordOffset,
    int32_t descSubOffset) ESP_READER_NOEXCEPT;

#if defined(__cplusplus)
}
#endif

#undef ESP_READER_NOEXCEPT

#endif
