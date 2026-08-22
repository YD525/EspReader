#include "../EspReader/EspReaderApi.h"

#define ESP_READER_C_ASSERT(name, expression) typedef char name[(expression) ? 1 : -1]

ESP_READER_C_ASSERT(EspReaderBoolMustBeOneByte, sizeof(EspReaderBool) == 1);
ESP_READER_C_ASSERT(EspReaderStatusMustBeFourBytes, sizeof(EspReaderStatus) == 4);
ESP_READER_C_ASSERT(DialResponseNodeLayoutMustBeStable, sizeof(C_DialResponseNode) == 16);

#if UINTPTR_MAX == UINT64_MAX
ESP_READER_C_ASSERT(LinkDial64LayoutMustBeStable, sizeof(C_LinkDIAL) == 40);
#else
ESP_READER_C_ASSERT(LinkDial32LayoutMustBeStable, sizeof(C_LinkDIAL) == 28);
#endif

int EspReaderCHeaderContract(void)
{
    return ESP_READER_ABI_VERSION == 1u && ESP_READER_STATUS_INTERNAL_ERROR == 7;
}
