#include "../UnitTest.h"

C_ASSERT(ALPC_HANDLEFLG_INDIRECT == 0x40000);
C_ASSERT(ALPC_INDIRECT_HANDLE_MAX == 512);

C_ASSERT(sizeof(ALPC_HANDLE_ATTR32) == 0x10);
C_ASSERT(FIELD_OFFSET(ALPC_HANDLE_ATTR32, Flags) == 0x00);
C_ASSERT(FIELD_OFFSET(ALPC_HANDLE_ATTR32, Handle) == 0x04);
C_ASSERT(FIELD_OFFSET(ALPC_HANDLE_ATTR32, ObjectType) == 0x08);
C_ASSERT(FIELD_OFFSET(ALPC_HANDLE_ATTR32, DesiredAccess) == 0x0C);
C_ASSERT(sizeof(ALPC_HANDLE_ATTR32) == FIELD_OFFSET(ALPC_HANDLE_ATTR32, DesiredAccess) + sizeof(ACCESS_MASK));

#ifdef _WIN64
C_ASSERT(sizeof(ALPC_HANDLE_ATTR) == 0x18);
C_ASSERT(FIELD_OFFSET(ALPC_HANDLE_ATTR, Handle) == 0x08);
C_ASSERT(FIELD_OFFSET(ALPC_HANDLE_ATTR, HandleAttrArray) == 0x08);
C_ASSERT(FIELD_OFFSET(ALPC_HANDLE_ATTR, ObjectType) == 0x10);
C_ASSERT(FIELD_OFFSET(ALPC_HANDLE_ATTR, HandleCount) == 0x10);
C_ASSERT(FIELD_OFFSET(ALPC_HANDLE_ATTR, DesiredAccess) == 0x14);
C_ASSERT(sizeof(ALPC_HANDLE_ATTR) == FIELD_OFFSET(ALPC_HANDLE_ATTR, DesiredAccess) + sizeof(ACCESS_MASK));
#else
C_ASSERT(sizeof(ALPC_HANDLE_ATTR) == 0x10);
C_ASSERT(FIELD_OFFSET(ALPC_HANDLE_ATTR, Handle) == 0x04);
C_ASSERT(FIELD_OFFSET(ALPC_HANDLE_ATTR, HandleAttrArray) == 0x04);
C_ASSERT(FIELD_OFFSET(ALPC_HANDLE_ATTR, ObjectType) == 0x08);
C_ASSERT(FIELD_OFFSET(ALPC_HANDLE_ATTR, HandleCount) == 0x08);
C_ASSERT(FIELD_OFFSET(ALPC_HANDLE_ATTR, DesiredAccess) == 0x0C);
C_ASSERT(sizeof(ALPC_HANDLE_ATTR) == FIELD_OFFSET(ALPC_HANDLE_ATTR, DesiredAccess) + sizeof(ACCESS_MASK));
#endif

static
VOID
NTAPI
AlpcAppendHexPointer(
    _Inout_updates_z_(Length) PWCHAR Buffer,
    _In_ ULONG Length,
    _In_ ULONG_PTR Value)
{
    static const WCHAR HexDigits[] = L"0123456789ABCDEF";
    ULONG Index;
    BOOLEAN Started;

    for (Index = 0; Buffer[Index] != UNICODE_NULL; Index++);

    Started = FALSE;
    for (ULONG Shift = sizeof(Value) * 8; Shift != 0;)
    {
        ULONG Digit;

        Shift -= 4;
        Digit = (ULONG)((Value >> Shift) & 0xF);
        if (Digit != 0 || Started || Shift == 0)
        {
            if (Index + 1 < Length)
            {
                Buffer[Index++] = HexDigits[Digit];
                Buffer[Index] = UNICODE_NULL;
            }
            Started = TRUE;
        }
    }
}

static
NTSTATUS
NTAPI
AlpcConnectWithHandleAttribute(
    _In_ PCUNICODE_STRING PortName,
    _In_ ULONG Flags,
    _In_opt_ PALPC_HANDLE_ATTR32 HandleAttrArray,
    _In_ ULONG HandleCount)
{
    UCHAR AttributesBuffer[sizeof(ALPC_MESSAGE_ATTRIBUTES) + sizeof(ALPC_HANDLE_ATTR)];
    PALPC_MESSAGE_ATTRIBUTES Attributes;
    PALPC_HANDLE_ATTR HandleAttribute;
    PORT_MESSAGE Message;
    SIZE_T MessageLength;
    HANDLE ClientPort;
    NTSTATUS Status;

    RtlZeroMemory(&Message, sizeof(Message));
    Message.u1.s1.TotalLength = sizeof(Message);
    MessageLength = sizeof(Message);

    RtlZeroMemory(AttributesBuffer, sizeof(AttributesBuffer));
    Attributes = (PALPC_MESSAGE_ATTRIBUTES)AttributesBuffer;
    Attributes->AllocatedAttributes = ALPC_MESSAGE_HANDLE_ATTRIBUTE;
    Attributes->ValidAttributes = ALPC_MESSAGE_HANDLE_ATTRIBUTE;

    HandleAttribute = (PALPC_HANDLE_ATTR)(Attributes + 1);
    HandleAttribute->Flags = Flags;
    HandleAttribute->HandleAttrArray = HandleAttrArray;
    HandleAttribute->HandleCount = HandleCount;

    Status = NtAlpcConnectPort(
        &ClientPort,
        (PUNICODE_STRING)PortName,
        NULL,
        NULL,
        0,
        NULL,
        &Message,
        &MessageLength,
        Attributes,
        NULL,
        NULL);
    if (NT_SUCCESS(Status))
    {
        NtClose(ClientPort);
    }

    return Status;
}

static
NTSTATUS
NTAPI
AlpcConnectWithIndirectHandleCount(
    _In_ PCUNICODE_STRING PortName,
    _In_ ULONG HandleCount)
{
    return AlpcConnectWithHandleAttribute(
        PortName,
        ALPC_HANDLEFLG_INDIRECT,
        NULL,
        HandleCount);
}

TEST_FUNC(Alpc)
{
    UCHAR Buffer[sizeof(ALPC_MESSAGE_ATTRIBUTES) + sizeof(ALPC_HANDLE_ATTR)];
    PALPC_MESSAGE_ATTRIBUTES Attributes;
    PALPC_HANDLE_ATTR HandleAttribute;
    WCHAR PortNameBuffer[96] = L"\\RPC Control\\KNSoft.NDK.Alpc.";
    UNICODE_STRING PortName;
    OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE ServerPort;
    SIZE_T RequiredSize;
    NTSTATUS Status;

    RequiredSize = 0;
    Status = AlpcInitializeMessageAttribute(
        ALPC_MESSAGE_HANDLE_ATTRIBUTE,
        NULL,
        0,
        &RequiredSize);
    TEST_OK(Status == STATUS_BUFFER_TOO_SMALL);
    TEST_OK(RequiredSize == sizeof(Buffer));
    TEST_OK(RequiredSize == sizeof(ALPC_MESSAGE_ATTRIBUTES) + FIELD_OFFSET(ALPC_HANDLE_ATTR, DesiredAccess) + sizeof(ACCESS_MASK));

    RtlZeroMemory(Buffer, sizeof(Buffer));
    Attributes = (PALPC_MESSAGE_ATTRIBUTES)Buffer;
    Status = AlpcInitializeMessageAttribute(
        ALPC_MESSAGE_HANDLE_ATTRIBUTE,
        Attributes,
        sizeof(Buffer),
        &RequiredSize);
    TEST_OK(Status == STATUS_SUCCESS);
    TEST_OK(RequiredSize == sizeof(Buffer));
    TEST_OK(Attributes->AllocatedAttributes == ALPC_MESSAGE_HANDLE_ATTRIBUTE);
    TEST_OK(Attributes->ValidAttributes == 0);

    HandleAttribute = (PALPC_HANDLE_ATTR)AlpcGetMessageAttribute(
        Attributes,
        ALPC_MESSAGE_HANDLE_ATTRIBUTE);
    TEST_OK(HandleAttribute != NULL);
    TEST_OK((PUCHAR)HandleAttribute == Buffer + sizeof(ALPC_MESSAGE_ATTRIBUTES));

    TEST_OK(AlpcGetMessageAttribute(Attributes, 1) == NULL);
    TEST_OK(AlpcGetMessageAttribute(Attributes, 2) == NULL);

    HandleAttribute->Flags = ALPC_HANDLEFLG_INDIRECT;
    HandleAttribute->HandleAttrArray = NULL;
    HandleAttribute->HandleCount = ALPC_INDIRECT_HANDLE_MAX;
    TEST_OK(HandleAttribute->Flags == 0x40000);
    TEST_OK(HandleAttribute->HandleCount == 512);

    AlpcAppendHexPointer(PortNameBuffer, RTL_NUMBER_OF(PortNameBuffer), (ULONG_PTR)NtCurrentProcessId());
    AlpcAppendHexPointer(PortNameBuffer, RTL_NUMBER_OF(PortNameBuffer), (ULONG_PTR)&PortNameBuffer);
    RtlInitUnicodeString(&PortName, PortNameBuffer);

    RtlZeroMemory(&ObjectAttributes, sizeof(ObjectAttributes));
    ObjectAttributes.Length = sizeof(ObjectAttributes);
    ObjectAttributes.ObjectName = &PortName;
    ObjectAttributes.Attributes = OBJ_CASE_INSENSITIVE;

    Status = NtAlpcCreatePort(&ServerPort, &ObjectAttributes, NULL);
    TEST_OK(Status == STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        ALPC_HANDLE_ATTR32 HandleAttrArray[2];

        RtlZeroMemory(HandleAttrArray, sizeof(HandleAttrArray));
        HandleAttrArray[0].Flags = ALPC_HANDLEFLG_INDIRECT;

        TEST_OK(AlpcConnectWithHandleAttribute(&PortName, 1, NULL, 0) == STATUS_INVALID_PARAMETER);
        TEST_OK(AlpcConnectWithHandleAttribute(&PortName, ALPC_HANDLEFLG_INDIRECT, HandleAttrArray, 2) == STATUS_INVALID_PARAMETER);
        TEST_OK(AlpcConnectWithIndirectHandleCount(&PortName, 1) == STATUS_INVALID_PARAMETER);
        TEST_OK(AlpcConnectWithIndirectHandleCount(&PortName, ALPC_INDIRECT_HANDLE_MAX) == STATUS_ACCESS_VIOLATION);
        TEST_OK(AlpcConnectWithIndirectHandleCount(&PortName, ALPC_INDIRECT_HANDLE_MAX + 1) == STATUS_LPC_HANDLE_COUNT_EXCEEDED);

        NtClose(ServerPort);
    }
}
