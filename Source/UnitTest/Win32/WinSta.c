#include "../UnitTest.h"

C_ASSERT(sizeof(SESSIONIDA) == 44);
C_ASSERT(FIELD_OFFSET(SESSIONIDA, State) == 40);
C_ASSERT(sizeof(SESSIONIDW) == 76);
C_ASSERT(FIELD_OFFSET(SESSIONIDW, State) == 72);
C_ASSERT(sizeof(WINSTATIONCONFIG) == 2664);
C_ASSERT(FIELD_OFFSET(WINSTATIONCONFIG, User.Password) == 210);
C_ASSERT(sizeof(WINSTATIONCLIENT) == 2296);
C_ASSERT(FIELD_OFFSET(WINSTATIONCLIENT, Password) == 124);
C_ASSERT(sizeof(PROTOCOLCOUNTERS) == 460);
C_ASSERT(sizeof(PROTOCOLSTATUS) == 1012);
C_ASSERT(sizeof(WINSTATIONINFORMATION) == 1216);
C_ASSERT(sizeof(WINSTATIONINFORMATIONEX_LEVEL1) == 1216);
C_ASSERT(FIELD_OFFSET(WINSTATIONINFORMATIONEX, Data) == 8);
C_ASSERT(sizeof(WINSTATIONREMOTEADDRESS) == 32);
C_ASSERT(FIELD_OFFSET(WINSTATIONREMOTEADDRESS, ipv4.sin_port) == 4);
C_ASSERT(FIELD_OFFSET(WINSTATIONREMOTEADDRESS, ipv6.sin6_addr) == 12);
C_ASSERT(FIELD_OFFSET(WINSTATIONREMOTEADDRESS, ipv6.sin6_scope_id) == 28);
C_ASSERT(sizeof(TS_COUNTER) == 24);
C_ASSERT(FIELD_OFFSET(TS_COUNTER, Value) == 8);
C_ASSERT(FIELD_OFFSET(TS_COUNTER, StartTime) == 16);
C_ASSERT(sizeof(TS_USER_SESSION) == 20);
#ifdef _WIN64
C_ASSERT(sizeof(TS_SYS_PROCESS_INFORMATION) == 184);
C_ASSERT(sizeof(TS_ALL_PROCESSES_INFO) == 24);
C_ASSERT(sizeof(EXECENVDATAEX) == 64);
C_ASSERT(sizeof(TS_PROPERTY_VALUE) == 24);
C_ASSERT(FIELD_OFFSET(TS_PROPERTY_VALUE, Value) == 8);
C_ASSERT(FIELD_OFFSET(TS_PROPERTY_VALUE, Value.Binary.Buffer) == 16);
C_ASSERT(sizeof(TS_USER_CERTIFICATES) == 16);
C_ASSERT(sizeof(TS_USER_CREDENTIALS) == 24);
#else
C_ASSERT(sizeof(TS_SYS_PROCESS_INFORMATION) == 136);
C_ASSERT(sizeof(TS_ALL_PROCESSES_INFO) == 12);
C_ASSERT(sizeof(EXECENVDATAEX) == 36);
C_ASSERT(sizeof(TS_PROPERTY_VALUE) == 20);
C_ASSERT(FIELD_OFFSET(TS_PROPERTY_VALUE, Value) == 4);
C_ASSERT(FIELD_OFFSET(TS_PROPERTY_VALUE, Value.Binary.Buffer) == 8);
C_ASSERT(sizeof(TS_USER_CERTIFICATES) == 12);
C_ASSERT(sizeof(TS_USER_CREDENTIALS) == 16);
#endif

typedef BOOLEAN (NTAPI* PFN_FREE_MEMORY)(PVOID Buffer);
typedef BOOLEAN (NTAPI* PFN_FREE_PROPERTY)(PTS_PROPERTY_VALUE Property);
typedef BOOLEAN (NTAPI* PFN_QUERY_CURRENT)(WINSTATIONINFOCLASS Class, PVOID Buffer, ULONG Length, PULONG ReturnLength);
typedef BOOLEAN (NTAPI* PFN_QUERY_BOOLEAN)(PBOOLEAN Value);
typedef BOOLEAN (NTAPI* PFN_QUERY_BOOL)(PBOOL Value);

TEST_FUNC(WinSta)
{
    HMODULE Module;
    PFN_FREE_MEMORY FreeMemory;
    PFN_FREE_PROPERTY FreeProperty;
    PFN_QUERY_CURRENT QueryCurrent;
    PFN_QUERY_BOOLEAN IsChildEnabled;
    PFN_QUERY_BOOL ActiveSessionExists;
    PTS_PROPERTY_VALUE Property;
    ULONG Type;
    ULONG ReturnLength;
    ULONG Error;
    ULONG Index;
    BOOLEAN Result;
    struct
    {
        ULONG Before;
        union
        {
            BOOL LongValue;
            BOOLEAN ByteValue;
            BYTE Bytes[sizeof(BOOL)];
        } Value;
        ULONG After;
    } Guard;

    UNREFERENCED_PARAMETER(TEST_PARAMETER_ARGC);
    UNREFERENCED_PARAMETER(TEST_PARAMETER_ARGV);

    Module = LoadLibraryExW(L"winsta.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (Module == NULL)
    {
        TEST_SKIP("WinSta.dll unavailable: %lu", GetLastError());
        return;
    }
    FreeMemory = (PFN_FREE_MEMORY)GetProcAddress(Module, "WinStationFreeMemory");
    FreeProperty = (PFN_FREE_PROPERTY)GetProcAddress(Module, "WinStationFreePropertyValue");
    QueryCurrent = (PFN_QUERY_CURRENT)GetProcAddress(Module, "WinStationQueryCurrentSessionInformation");
    IsChildEnabled = (PFN_QUERY_BOOLEAN)GetProcAddress(Module, "WinStationIsChildSessionsEnabled");
    ActiveSessionExists = (PFN_QUERY_BOOL)GetProcAddress(Module, "WinStationActiveSessionExists");

    if (FreeMemory != NULL)
    {
        TEST_OK(FreeMemory(NULL) == TRUE);
        Property = LocalAlloc(LPTR, sizeof(*Property));
        TEST_OK(Property != NULL);
        if (Property != NULL)
        {
            TEST_OK(FreeMemory(Property) == TRUE);
        }
    }
    if (FreeProperty != NULL)
    {
        for (Type = TS_PROPERTY_TYPE_ULONG; Type <= TS_PROPERTY_TYPE_GUID; Type++)
        {
            Property = LocalAlloc(LPTR, sizeof(*Property));
            TEST_OK(Property != NULL);
            if (Property == NULL)
            {
                break;
            }
            Property->Type = (USHORT)Type;
            if (Type == TS_PROPERTY_TYPE_STRING || Type == TS_PROPERTY_TYPE_BINARY)
            {
                Property->Value.Binary.Length = 4;
                Property->Value.Binary.Buffer = LocalAlloc(LPTR, 8);
                TEST_OK(Property->Value.Binary.Buffer != NULL);
            }
            TEST_OK(FreeProperty(Property) == TRUE);
        }
    }
    if (QueryCurrent != NULL)
    {
        RtlFillMemory(&Guard, sizeof(Guard), 0xCC);
        ReturnLength = MAXULONG;
        // Rejected before RPC; only the return-length output is cleared.
        Result = QueryCurrent(MaxWinStationInfoClass, &Guard.Value, sizeof(Guard.Value), &ReturnLength);
        Error = GetLastError();
        TEST_OK(Result == FALSE);
        TEST_OK(Error == ERROR_INVALID_PARAMETER);
        TEST_OK(ReturnLength == 0);
        TEST_OK(Guard.Before == 0xCCCCCCCC && Guard.Value.LongValue == (LONG)0xCCCCCCCC);
        TEST_OK(Guard.After == 0xCCCCCCCC);
    }
    if (IsChildEnabled != NULL)
    {
        RtlFillMemory(&Guard, sizeof(Guard), 0xCC);
        Result = IsChildEnabled(&Guard.Value.ByteValue);
        if (Result)
        {
            TEST_OK(Guard.Value.ByteValue == FALSE || Guard.Value.ByteValue == TRUE);
            for (Index = sizeof(BOOLEAN); Index < sizeof(Guard.Value); Index++)
            {
                TEST_OK(Guard.Value.Bytes[Index] == 0xCC);
            }
        }
        else
        {
            TEST_SKIP("Child-session query unavailable: %lu", GetLastError());
        }
        TEST_OK(Guard.Before == 0xCCCCCCCC && Guard.After == 0xCCCCCCCC);
    }
    if (ActiveSessionExists != NULL)
    {
        RtlFillMemory(&Guard, sizeof(Guard), 0xCC);
        Result = ActiveSessionExists(&Guard.Value.LongValue);
        if (Result)
        {
            TEST_OK(Guard.Value.LongValue == FALSE || Guard.Value.LongValue == TRUE);
        }
        else
        {
            TEST_SKIP("Active-session query unavailable: %lu", GetLastError());
        }
        TEST_OK(Guard.Before == 0xCCCCCCCC && Guard.After == 0xCCCCCCCC);
    }
    FreeLibrary(Module);
}
