#pragma once

#include "../../MinDef.h"

EXTERN_C_START

/* phnt */

/**
 * Represents the root of a red-black tree.
 */
typedef struct _RTL_RB_TREE
{
    PRTL_BALANCED_NODE Root;
    union
    {
        UCHAR Encoded : 1;
        PRTL_BALANCED_NODE Min;
    };
} RTL_RB_TREE, *PRTL_RB_TREE;

#if (NTDDI_VERSION >= NTDDI_WIN8)

/**
 * The RtlRbInsertNodeEx routine inserts a node into a red-black balanced binary tree at a specified position.
 *
 * \param Tree A pointer to the red-black tree.
 * \param Parent An optional pointer to the parent node under which the new node is inserted.
 * \param Right If `TRUE`, the node is inserted as the right child of the parent; otherwise as the left child.
 * \param Node A pointer to the balanced node to insert into the tree.
 * \return `TRUE` if the node was inserted successfully, otherwise `FALSE`.
 */
NTSYSAPI
BOOLEAN
NTAPI
RtlRbInsertNodeEx(
    _In_ PRTL_RB_TREE Tree,
    _In_opt_ PRTL_BALANCED_NODE Parent,
    _In_ BOOLEAN Right,
    _Out_ PRTL_BALANCED_NODE Node);

/**
 * The RtlRbRemoveNode routine removes a node from a red-black balanced binary tree.
 *
 * \param Tree A pointer to the red-black tree.
 * \param Node A pointer to the balanced node to remove from the tree.
 */
NTSYSAPI
BOOLEAN
NTAPI
RtlRbRemoveNode(
    _In_ PRTL_RB_TREE Tree,
    _In_ PRTL_BALANCED_NODE Node);

#endif

#if (NTDDI_VERSION >= NTDDI_WIN11_ZN)

// rev
/**
 * The RtlCompareExchangePointerMapping routine atomically exchanges a pair of pointer-mapping nodes in a red-black
 * tree.
 *
 * \param Node1 A pointer to the first balanced node.
 * \param Node2 A pointer to the second balanced node.
 * \param Node3 A pointer to a variable that receives a balanced node.
 * \param Node4 A pointer to a variable that receives a balanced node.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlCompareExchangePointerMapping( 
    _In_ PRTL_BALANCED_NODE Node1,
    _In_ PRTL_BALANCED_NODE Node2,
    _Out_ PRTL_BALANCED_NODE *Node3,
    _Out_ PRTL_BALANCED_NODE *Node4);

// rev
/**
 * The RtlQueryPointerMapping routine queries the pointer-mapping entries associated with a red-black tree.
 *
 * \param Tree A pointer to the red-black tree.
 * \param Children A pointer to a balanced node that receives the queried mapping.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlQueryPointerMapping(
    _In_ PRTL_RB_TREE Tree,
    _Inout_ PRTL_BALANCED_NODE Children);

// rev
/**
 * The RtlRemovePointerMapping routine removes the pointer-mapping entries associated with a red-black tree.
 *
 * \param Tree A pointer to the red-black tree.
 * \param Children A pointer to a balanced node describing the mapping to remove.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlRemovePointerMapping(
    _In_ PRTL_RB_TREE Tree,
    _Inout_ PRTL_BALANCED_NODE Children);

#endif

typedef struct _RTL_AVL_TREE RTL_AVL_TREE, *PRTL_AVL_TREE;
// RtlAvlRemoveNode
/**
 * The RtlAvlRemoveNode routine removes a node from an Adelson-Velsky/Landis (AVL) balanced binary tree.
 *
 * \param Root A pointer to the root pointer of the AVL tree.
 * \param Node A pointer to the balanced node to remove from the tree.
 */
NTSYSAPI
VOID
NTAPI
RtlAvlRemoveNode(
    _Inout_ PRTL_BALANCED_NODE *Root,
    _In_ PRTL_BALANCED_NODE Node
    );

// RtlAvlInsertNodeEx
//NTSYSAPI
//BOOLEAN
//NTAPI
//RtlAreBitsClearEx(
//    _In_ PRTL_BITMAP_EX BitMapHeader,
//    _In_ ULONGLONG StartingIndex,
//    _In_ ULONGLONG Length
//    );

// rev
/**
 * The RtlAvlInsertNodeEx routine inserts a node into an AVL tree at a specified parent and side, rebalancing as
 * required.
 *
 * \param Root A pointer to a variable that references the root of the AVL tree.
 * \param Parent An optional pointer to the parent node under which the new node is inserted.
 * \param Right If `TRUE`, the node is inserted as the right child of the parent; otherwise as the left child.
 * \param Node A pointer to the RTL_BALANCED_NODE to insert.
 * \return CHAR The balance adjustment applied to the tree as a result of the insertion.
 */
NTSYSAPI
char
NTAPI
RtlAvlInsertNodeEx(
    _Inout_ PRTL_BALANCED_NODE *Root,
    _In_opt_ PRTL_BALANCED_NODE Parent,
    _In_ BOOLEAN Right,
    _In_ PRTL_BALANCED_NODE Node
    );


EXTERN_C_END
