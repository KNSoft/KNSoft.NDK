#pragma once

#include "../../MinDef.h"
#include "../ErrorHandling.h"

EXTERN_C_START

/* Addendum to SList */

NTSYSAPI
PSLIST_ENTRY
NTAPI
RtlInterlockedPushListSList(
    _Inout_ PSLIST_HEADER ListHead,
    _Inout_ __drv_aliasesMem PSLIST_ENTRY List,
    _Inout_ PSLIST_ENTRY ListEnd,
    _In_ DWORD Count
    );

/* wdm.h */

//
//  Doubly-linked list manipulation routines.
//

#define InitializeListHead32(ListHead) ((ListHead)->Flink = (ListHead)->Blink = PtrToUlong((ListHead)))

#define RTL_STATIC_LIST_HEAD(x) LIST_ENTRY x = { &x, &x }

FORCEINLINE
VOID
InitializeListHead(
    _Out_ PLIST_ENTRY ListHead)
{
    ListHead->Flink = ListHead->Blink = ListHead;
    return;
}

_Must_inspect_result_
BOOLEAN
CFORCEINLINE
IsListEmpty(
    _In_ const LIST_ENTRY* ListHead)
{
    return (BOOLEAN)(ListHead->Flink == ListHead);
}

FORCEINLINE
BOOLEAN
RemoveEntryListUnsafe(
    _In_ PLIST_ENTRY Entry)
{
    PLIST_ENTRY Blink;
    PLIST_ENTRY Flink;

    Flink = Entry->Flink;
    Blink = Entry->Blink;
    Blink->Flink = Flink;
    Flink->Blink = Blink;
    return (BOOLEAN)(Flink == Blink);
}

#if defined(NO_KERNEL_LIST_ENTRY_CHECKS)

FORCEINLINE
BOOLEAN
RemoveEntryList(
    _In_ PLIST_ENTRY Entry)
{
    PLIST_ENTRY Blink;
    PLIST_ENTRY Flink;

    Flink = Entry->Flink;
    Blink = Entry->Blink;
    Blink->Flink = Flink;
    Flink->Blink = Blink;
    return (BOOLEAN)(Flink == Blink);
}

FORCEINLINE
PLIST_ENTRY
RemoveHeadList(
    _Inout_ PLIST_ENTRY ListHead)
{
    PLIST_ENTRY Flink;
    PLIST_ENTRY Entry;

    Entry = ListHead->Flink;
    Flink = Entry->Flink;
    ListHead->Flink = Flink;
    Flink->Blink = ListHead;
    return Entry;
}

FORCEINLINE
PLIST_ENTRY
RemoveTailList(
    _Inout_ PLIST_ENTRY ListHead)
{
    PLIST_ENTRY Blink;
    PLIST_ENTRY Entry;

    Entry = ListHead->Blink;
    Blink = Entry->Blink;
    ListHead->Blink = Blink;
    Blink->Flink = ListHead;
    return Entry;
}

FORCEINLINE
VOID
InsertTailList(
    _Inout_ PLIST_ENTRY ListHead,
    _Inout_ __drv_aliasesMem PLIST_ENTRY Entry)
{
    PLIST_ENTRY Blink;

    Blink = ListHead->Blink;
    Entry->Flink = ListHead;
    Entry->Blink = Blink;
    Blink->Flink = Entry;
    ListHead->Blink = Entry;
    return;
}

FORCEINLINE
VOID
InsertHeadList(
    _Inout_ PLIST_ENTRY ListHead,
    _Inout_ __drv_aliasesMem PLIST_ENTRY Entry)
{
    PLIST_ENTRY Flink;

    Flink = ListHead->Flink;
    Entry->Flink = Flink;
    Entry->Blink = ListHead;
    Flink->Blink = Entry;
    ListHead->Flink = Entry;
    return;
}

FORCEINLINE
VOID
AppendTailList(
    _Inout_ PLIST_ENTRY ListHead,
    _Inout_ PLIST_ENTRY ListToAppend)
{
    PLIST_ENTRY ListEnd = ListHead->Blink;

    ListHead->Blink->Flink = ListToAppend;
    ListHead->Blink = ListToAppend->Blink;
    ListToAppend->Blink->Flink = ListHead;
    ListToAppend->Blink = ListEnd;
    return;
}

#else // NO_KERNEL_LIST_ENTRY_CHECKS

//++
//VOID
//FatalListEntryError (
//    _In_ PVOID p1,
//    _In_ PVOID p2,
//    _In_ PVOID p3
//    );
//
// Routine Description:
//
//    This routine reports a fatal list entry error.  It is implemented here as a
//    wrapper around RtlFailFast so that alternative reporting mechanisms (such
//    as simply logging and trying to continue) can be easily switched in.
//
// Arguments:
//
//    p1 - Supplies the first failure parameter.
//
//    p2 - Supplies the second failure parameter.
//
//    p3 - Supplies the third failure parameter.
//
//Return Value:
//
//    None.
//--

FORCEINLINE
VOID
FatalListEntryError(
    _In_ PVOID p1,
    _In_ PVOID p2,
    _In_ PVOID p3)
{
    UNREFERENCED_PARAMETER(p1);
    UNREFERENCED_PARAMETER(p2);
    UNREFERENCED_PARAMETER(p3);

    RtlFailFast(FAST_FAIL_CORRUPT_LIST_ENTRY);
}

FORCEINLINE
VOID
RtlpCheckListEntry(
    _In_ PLIST_ENTRY Entry)
{
    if ((((Entry->Flink)->Blink) != Entry) || (((Entry->Blink)->Flink) != Entry))
    {
        FatalListEntryError((PVOID)(Entry),
                            (PVOID)((Entry->Flink)->Blink),
                            (PVOID)((Entry->Blink)->Flink));
    }
}


FORCEINLINE
BOOLEAN
RemoveEntryList(
    _In_ PLIST_ENTRY Entry)
{
    PLIST_ENTRY PrevEntry;
    PLIST_ENTRY NextEntry;

    NextEntry = Entry->Flink;
    PrevEntry = Entry->Blink;
    if ((NextEntry->Blink != Entry) || (PrevEntry->Flink != Entry))
    {
        FatalListEntryError((PVOID)PrevEntry,
                            (PVOID)Entry,
                            (PVOID)NextEntry);
    }

    PrevEntry->Flink = NextEntry;
    NextEntry->Blink = PrevEntry;
    return (BOOLEAN)(PrevEntry == NextEntry);
}

FORCEINLINE
PLIST_ENTRY
RemoveHeadList(
    _Inout_ PLIST_ENTRY ListHead)
{
    PLIST_ENTRY Entry;
    PLIST_ENTRY NextEntry;

    Entry = ListHead->Flink;

#if DBG
    RtlpCheckListEntry(ListHead);
#endif

    NextEntry = Entry->Flink;
    if ((Entry->Blink != ListHead) || (NextEntry->Blink != Entry))
    {
        FatalListEntryError((PVOID)ListHead,
                            (PVOID)Entry,
                            (PVOID)NextEntry);
    }

    ListHead->Flink = NextEntry;
    NextEntry->Blink = ListHead;

    return Entry;
}

FORCEINLINE
PLIST_ENTRY
RemoveTailList(
    _Inout_ PLIST_ENTRY ListHead)
{
    PLIST_ENTRY Entry;
    PLIST_ENTRY PrevEntry;

    Entry = ListHead->Blink;

#if DBG
    RtlpCheckListEntry(ListHead);
#endif

    PrevEntry = Entry->Blink;
    if ((Entry->Flink != ListHead) || (PrevEntry->Flink != Entry))
    {
        FatalListEntryError((PVOID)PrevEntry,
                            (PVOID)Entry,
                            (PVOID)ListHead);
    }

    ListHead->Blink = PrevEntry;
    PrevEntry->Flink = ListHead;
    return Entry;
}


FORCEINLINE
VOID
InsertTailList(
    _Inout_ PLIST_ENTRY ListHead,
    _Out_ __drv_aliasesMem PLIST_ENTRY Entry)
{
    PLIST_ENTRY PrevEntry;

#if DBG
    RtlpCheckListEntry(ListHead);
#endif

    PrevEntry = ListHead->Blink;
    if (PrevEntry->Flink != ListHead)
    {
        FatalListEntryError((PVOID)PrevEntry,
                            (PVOID)ListHead,
                            (PVOID)PrevEntry->Flink);
    }

    Entry->Flink = ListHead;
    Entry->Blink = PrevEntry;
    PrevEntry->Flink = Entry;
    ListHead->Blink = Entry;
    return;
}

FORCEINLINE
VOID
InsertHeadList(
    _Inout_ PLIST_ENTRY ListHead,
    _Out_ __drv_aliasesMem PLIST_ENTRY Entry)
{
    PLIST_ENTRY NextEntry;

#if DBG
    RtlpCheckListEntry(ListHead);
#endif

    NextEntry = ListHead->Flink;
    if (NextEntry->Blink != ListHead)
    {
        FatalListEntryError((PVOID)ListHead,
                            (PVOID)NextEntry,
                            (PVOID)NextEntry->Blink);
    }

    Entry->Flink = NextEntry;
    Entry->Blink = ListHead;
    NextEntry->Blink = Entry;
    ListHead->Flink = Entry;
    return;
}

FORCEINLINE
VOID
AppendTailList(
    _Inout_ PLIST_ENTRY ListHead,
    _Inout_ PLIST_ENTRY ListToAppend)
{
    PLIST_ENTRY ListEnd = ListHead->Blink;

    RtlpCheckListEntry(ListHead);
    RtlpCheckListEntry(ListToAppend);
    ListHead->Blink->Flink = ListToAppend;
    ListHead->Blink = ListToAppend->Blink;
    ListToAppend->Blink->Flink = ListHead;
    ListToAppend->Blink = ListEnd;
    return;
}

#endif // NO_KERNEL_LIST_ENTRY_CHECKS

_Must_inspect_result_
FORCEINLINE
BOOLEAN
IsSingleListEmpty(
    _Inout_ PSINGLE_LIST_ENTRY ListHead)
{
    return ListHead->Next == NULL;
}

FORCEINLINE
PSINGLE_LIST_ENTRY
PopEntryList(
    _Inout_ PSINGLE_LIST_ENTRY ListHead)
{
    PSINGLE_LIST_ENTRY FirstEntry;

    FirstEntry = ListHead->Next;
    if (FirstEntry != NULL)
    {
        ListHead->Next = FirstEntry->Next;
    }

    return FirstEntry;
}

FORCEINLINE
VOID
PushEntryList(
    _Inout_ PSINGLE_LIST_ENTRY ListHead,
    _Inout_ __drv_aliasesMem PSINGLE_LIST_ENTRY Entry)
{
    Entry->Next = ListHead->Next;
    ListHead->Next = Entry;
    return;
}

//
// Single list volatile accessors
//

_Must_inspect_result_
FORCEINLINE
BOOLEAN
IsSingleListEmptyNoFence(
    _Inout_ PSINGLE_LIST_ENTRY ListHead)
{
    return ReadPointerNoFence((PVOID*)&ListHead->Next) == NULL;
}

FORCEINLINE
PSINGLE_LIST_ENTRY
PopEntryListNoFence(
    _Inout_ PSINGLE_LIST_ENTRY ListHead)
{
    PSINGLE_LIST_ENTRY FirstEntry;

    FirstEntry = ListHead->Next;
    if (FirstEntry != NULL)
    {
        WritePointerNoFence((PVOID*)&ListHead->Next, FirstEntry->Next);
    }

    return FirstEntry;
}

FORCEINLINE
VOID
PushEntryListNoFence(
    _Inout_ PSINGLE_LIST_ENTRY ListHead,
    _Inout_ __drv_aliasesMem PSINGLE_LIST_ENTRY Entry)
{
    Entry->Next = ListHead->Next;
    WritePointerNoFence((PVOID*)&ListHead->Next, Entry);
    return;
}

//
// List volatile accessors
//

FORCEINLINE
BOOLEAN
RemoveEntryListNoFence(
    _In_ PLIST_ENTRY Entry)
{
    PLIST_ENTRY PrevEntry;
    PLIST_ENTRY NextEntry;

    NextEntry = (PLIST_ENTRY)ReadPointerNoFence((volatile const PVOID*)&Entry->Flink);
    PrevEntry = (PLIST_ENTRY)ReadPointerNoFence((volatile const PVOID*)&Entry->Blink);

    if ((ReadPointerNoFence((volatile const PVOID*)&NextEntry->Blink) != Entry) ||
        (ReadPointerNoFence((volatile const PVOID*)&PrevEntry->Flink) != Entry))
    {
        FatalListEntryError((PVOID)PrevEntry,
                            (PVOID)Entry,
                            (PVOID)NextEntry);
    }

    WritePointerNoFence((volatile PVOID*)&PrevEntry->Flink, NextEntry);
    WritePointerNoFence((volatile PVOID*)&NextEntry->Blink, PrevEntry);
    return (BOOLEAN)(PrevEntry == NextEntry);
}

FORCEINLINE
PLIST_ENTRY
RemoveHeadListNoFence(
    _Inout_ PLIST_ENTRY ListHead)
{
    PLIST_ENTRY Entry;
    PLIST_ENTRY NextEntry;

    Entry = (PLIST_ENTRY)ReadPointerNoFence((volatile const PVOID*)&ListHead->Flink);

#if DBG
    RtlpCheckListEntry(ListHead);
#endif

    NextEntry = (PLIST_ENTRY)ReadPointerNoFence((volatile const PVOID*)&Entry->Flink);
    if ((ReadPointerNoFence((volatile const PVOID*)&Entry->Blink) != ListHead) ||
        (ReadPointerNoFence((volatile const PVOID*)&NextEntry->Blink) != Entry))
    {
        FatalListEntryError((PVOID)ListHead,
                            (PVOID)Entry,
                            (PVOID)NextEntry);
    }

    WritePointerNoFence((volatile PVOID*)&ListHead->Flink, NextEntry);
    WritePointerNoFence((volatile PVOID*)&NextEntry->Blink, ListHead);
    return Entry;
}

FORCEINLINE
PLIST_ENTRY
RemoveTailListNoFence(
    _Inout_ PLIST_ENTRY ListHead)
{
    PLIST_ENTRY Entry;
    PLIST_ENTRY PrevEntry;

    Entry = (PLIST_ENTRY)ReadPointerNoFence((volatile const PVOID*)&ListHead->Blink);

#if DBG
    RtlpCheckListEntry(ListHead);
#endif

    PrevEntry = (PLIST_ENTRY)ReadPointerNoFence((volatile const PVOID*)&Entry->Blink);
    if ((ReadPointerNoFence((volatile const PVOID*)&Entry->Flink) != ListHead) ||
        (ReadPointerNoFence((volatile const PVOID*)&PrevEntry->Flink) != Entry))
    {
        FatalListEntryError((PVOID)PrevEntry,
                            (PVOID)Entry,
                            (PVOID)ListHead);
    }

    WritePointerNoFence((volatile PVOID*)&ListHead->Blink, PrevEntry);
    WritePointerNoFence((volatile PVOID*)&PrevEntry->Flink, ListHead);
    return Entry;
}

FORCEINLINE
VOID
InsertTailListNoFence(
    _Inout_ PLIST_ENTRY ListHead,
    _Inout_ __drv_aliasesMem PLIST_ENTRY Entry)
{
    PLIST_ENTRY PrevEntry;

#if DBG
    RtlpCheckListEntry(ListHead);
#endif

    PrevEntry = (PLIST_ENTRY)ReadPointerNoFence((volatile const PVOID*)&ListHead->Blink);
    if (ReadPointerNoFence((volatile const PVOID*)&PrevEntry->Flink) != ListHead)
    {
        FatalListEntryError((PVOID)PrevEntry,
                            (PVOID)ListHead,
                            (PVOID)PrevEntry->Flink);
    }

    WritePointerNoFence((volatile PVOID*)&Entry->Flink, ListHead);
    WritePointerNoFence((volatile PVOID*)&Entry->Blink, PrevEntry);
    WritePointerNoFence((volatile PVOID*)&PrevEntry->Flink, Entry);
    WritePointerNoFence((volatile PVOID*)&ListHead->Blink, Entry);
    return;
}

FORCEINLINE
VOID
InsertHeadListNoFence(
    _Inout_ PLIST_ENTRY ListHead,
    _Inout_ __drv_aliasesMem PLIST_ENTRY Entry)
{
    PLIST_ENTRY NextEntry;

#if DBG
    RtlpCheckListEntry(ListHead);
#endif

    NextEntry = (PLIST_ENTRY)ReadPointerNoFence((volatile const PVOID*)&ListHead->Flink);
    if (ReadPointerNoFence((volatile const PVOID*)&NextEntry->Blink) != ListHead)
    {
        FatalListEntryError((PVOID)ListHead,
                            (PVOID)NextEntry,
                            (PVOID)NextEntry->Blink);
    }

    WritePointerNoFence((volatile PVOID*)&Entry->Flink, NextEntry);
    WritePointerNoFence((volatile PVOID*)&Entry->Blink, ListHead);
    WritePointerNoFence((volatile PVOID*)&NextEntry->Blink, Entry);
    WritePointerNoFence((volatile PVOID*)&ListHead->Flink, Entry);
    return;
}

FORCEINLINE
VOID
AppendTailListNoFence(
    _Inout_ PLIST_ENTRY ListHead,
    _Inout_ PLIST_ENTRY ListToAppend)
{
    PLIST_ENTRY ListEnd = (PLIST_ENTRY)ReadPointerNoFence((volatile const PVOID*)&ListHead->Blink);

    RtlpCheckListEntry(ListHead);
    RtlpCheckListEntry(ListToAppend);

    WritePointerNoFence((volatile PVOID*)&ListHead->Blink->Flink, ListToAppend);
    WritePointerNoFence((volatile PVOID*)&ListHead->Blink, ListToAppend->Blink);
    WritePointerNoFence((volatile PVOID*)&ListToAppend->Blink->Flink, ListHead);
    WritePointerNoFence((volatile PVOID*)&ListToAppend->Blink, ListEnd);
    return;
}

// Rtl-prefixed aliases for list helpers.
#define RtlInitializeListHead InitializeListHead
#define RtlInitializeListHead32 InitializeListHead32
#define RtlIsListEmpty IsListEmpty
#define RtlRemoveEntryListUnsafe RemoveEntryListUnsafe
#define RtlRemoveEntryList RemoveEntryList
#define RtlRemoveHeadList RemoveHeadList
#define RtlRemoveTailList RemoveTailList
#define RtlInsertTailList InsertTailList
#define RtlInsertHeadList InsertHeadList
#define RtlAppendTailList AppendTailList
#define RtlPopEntryList PopEntryList
#define RtlPushEntryList PushEntryList

EXTERN_C_END
