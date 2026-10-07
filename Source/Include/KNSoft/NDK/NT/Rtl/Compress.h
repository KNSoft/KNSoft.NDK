#pragma once

#include "../MinDef.h"

EXTERN_C_START

/* ntifs.h */

#define COMPRESSION_FORMAT_MAX           (0x0008)
#define COMPRESSION_ENGINE_MAX           (0x0200)

/**
 * Masks for extracting the compression format and engine from a combined value.
 */
#define COMPRESSION_FORMAT_MASK          (0x00FF)
#define COMPRESSION_ENGINE_MASK          (0xFF00)
#define COMPRESSION_FORMAT_ENGINE_MASK   (COMPRESSION_FORMAT_MASK |         \
                                          COMPRESSION_ENGINE_MASK)

//
//  Compressed Data Information structure.  This structure is
//  used to describe the state of a compressed data buffer,
//  whose uncompressed size is known.  All compressed chunks
//  described by this structure must be compressed with the
//  same format.  On compressed reads, this entire structure
//  is an output, and on compressed writes the entire structure
//  is an input.
//

/**
 * Describes the format and parameters of a compressed data buffer.
 */
typedef struct _COMPRESSED_DATA_INFO
{

//
//  Code for the compression format (and engine) as
//  defined in ntrtl.h.  Note that COMPRESSION_FORMAT_NONE
//  and COMPRESSION_FORMAT_DEFAULT are invalid if
//  any of the described chunks are compressed.
//

    USHORT CompressionFormatAndEngine;

    //
    //  Since chunks and compression units are expected to be
    //  powers of 2 in size, we express then log2.  So, for
    //  example (1 << ChunkShift) == ChunkSizeInBytes.  The
    //  ClusterShift indicates how much space must be saved
    //  to successfully compress a compression unit - each
    //  successfully compressed compression unit must occupy
    //  at least one cluster less in bytes than an uncompressed
    //  compression unit.
    //

    UCHAR CompressionUnitShift;
    UCHAR ChunkShift;
    UCHAR ClusterShift;
    UCHAR Reserved;

    //
    //  This is the number of entries in the CompressedChunkSizes
    //  array.
    //

    USHORT NumberOfChunks;

    //
    //  This is an array of the sizes of all chunks resident
    //  in the compressed data buffer.  There must be one entry
    //  in this array for each chunk possible in the uncompressed
    //  buffer size.  A size of FSRTL_CHUNK_SIZE indicates the
    //  corresponding chunk is uncompressed and occupies exactly
    //  that size.  A size of 0 indicates that the corresponding
    //  chunk contains nothing but binary 0's, and occupies no
    //  space in the compressed data.  All other sizes must be
    //  less than FSRTL_CHUNK_SIZE, and indicate the exact size
    //  of the compressed data in bytes.
    //

    ULONG CompressedChunkSizes[ANYSIZE_ARRAY];

} COMPRESSED_DATA_INFO;
typedef COMPRESSED_DATA_INFO *PCOMPRESSED_DATA_INFO;

#ifdef _NT_STATIC_RTL_COMPRESS_
#define NT_RTL_COMPRESS_API
#else
#define NT_RTL_COMPRESS_API /**
 * The RtlGetCompressionWorkSpaceSize routine determines the size of the work space required by the compression and
 * decompression routines.
 *
 * \param CompressionFormatAndEngine The compression format and engine (for example, COMPRESSION_FORMAT_LZNT1 combined
 * with an engine value).
 * \param CompressBufferWorkSpaceSize A pointer to a variable that receives the work space size required to compress a
 * buffer.
 * \param CompressFragmentWorkSpaceSize A pointer to a variable that receives the work space size required to compress a
 * fragment.
 * \return NTSTATUS Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlgetcompressionworkspacesize
 */
NTSYSAPI
#endif

NT_RTL_COMPRESS_API
NTSTATUS
NTAPI
RtlGetCompressionWorkSpaceSize(
    _In_ USHORT CompressionFormatAndEngine,
    _Out_ PULONG CompressBufferWorkSpaceSize,
    _Out_ PULONG CompressFragmentWorkSpaceSize
);

NT_RTL_COMPRESS_API
/**
 * The RtlCompressBuffer routine compresses a buffer using the specified compression format and engine.
 *
 * \param CompressionFormatAndEngine The compression format (COMPRESSION_FORMAT_*) combined with the engine
 * (COMPRESSION_ENGINE_*).
 * \param UncompressedBuffer The data to compress.
 * \param UncompressedBufferSize The size, in bytes, of UncompressedBuffer.
 * \param CompressedBuffer A buffer that receives the compressed data.
 * \param CompressedBufferSize The size, in bytes, of CompressedBuffer.
 * \param UncompressedChunkSize The chunk size used during compression (typically 4096).
 * \param FinalCompressedSize Receives the size, in bytes, of the compressed data.
 * \param WorkSpace A workspace buffer sized per RtlGetCompressionWorkSpaceSize.
 * \return NTSTATUS Successful or errant status.
 */
NTSTATUS
NTAPI
RtlCompressBuffer(
    _In_ USHORT CompressionFormatAndEngine,
    _In_reads_bytes_(UncompressedBufferSize) PUCHAR UncompressedBuffer,
    _In_ ULONG UncompressedBufferSize,
    _Out_writes_bytes_to_(CompressedBufferSize, *FinalCompressedSize) PUCHAR CompressedBuffer,
    _In_ ULONG CompressedBufferSize,
    _In_ ULONG UncompressedChunkSize,
    _Out_ PULONG FinalCompressedSize,
    _In_ PVOID WorkSpace
);

NT_RTL_COMPRESS_API
/**
 * The RtlDecompressBuffer routine decompresses an entire compressed buffer.
 *
 * \param CompressionFormat The compression format used to compress the buffer.
 * \param UncompressedBuffer A buffer that receives the decompressed data.
 * \param UncompressedBufferSize The size, in bytes, of the uncompressed buffer.
 * \param CompressedBuffer A pointer to the compressed data.
 * \param CompressedBufferSize The size, in bytes, of the compressed buffer.
 * \param FinalUncompressedSize A pointer to a variable that receives the number of bytes written to the uncompressed
 * buffer.
 * \return NTSTATUS Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtldecompressbuffer
 */
NTSTATUS
NTAPI
RtlDecompressBuffer(
    _In_ USHORT CompressionFormat,
    _Out_writes_bytes_to_(UncompressedBufferSize, *FinalUncompressedSize) PUCHAR UncompressedBuffer,
    _In_ ULONG UncompressedBufferSize,
    _In_reads_bytes_(CompressedBufferSize) PUCHAR CompressedBuffer,
    _In_ ULONG CompressedBufferSize,
    _Out_ PULONG FinalUncompressedSize
);

#if (NTDDI_VERSION >= NTDDI_WIN8) || defined(_NT_STATIC_RTL_COMPRESS_)
NT_RTL_COMPRESS_API
/**
 * The RtlDecompressBufferEx routine decompresses a buffer using the specified compression format, with an optional
 * caller-supplied workspace.
 *
 * \param CompressionFormat The compression format (COMPRESSION_FORMAT_*) of the compressed data.
 * \param UncompressedBuffer A buffer that receives the decompressed data.
 * \param UncompressedBufferSize The size, in bytes, of UncompressedBuffer.
 * \param CompressedBuffer The compressed data to decompress.
 * \param CompressedBufferSize The size, in bytes, of CompressedBuffer.
 * \param FinalUncompressedSize Receives the size, in bytes, of the decompressed data.
 * \param WorkSpace An optional workspace buffer sized per RtlGetCompressionWorkSpaceSize.
 * \return NTSTATUS Successful or errant status.
 */
NTSTATUS
NTAPI
RtlDecompressBufferEx(
    _In_ USHORT CompressionFormat,
    _Out_writes_bytes_to_(UncompressedBufferSize, *FinalUncompressedSize) PUCHAR UncompressedBuffer,
    _In_ ULONG UncompressedBufferSize,
    _In_reads_bytes_(CompressedBufferSize) PUCHAR CompressedBuffer,
    _In_ ULONG CompressedBufferSize,
    _Out_ PULONG FinalUncompressedSize,
    _In_opt_ PVOID WorkSpace
);
#endif

#if (NTDDI_VERSION >= NTDDI_WINBLUE) || defined(_NT_STATIC_RTL_COMPRESS_)
NT_RTL_COMPRESS_API
/**
 * The RtlDecompressBufferEx2 routine decompresses a buffer using the specified compression format and chunk size, with
 * an optional workspace.
 *
 * \param CompressionFormat The compression format (COMPRESSION_FORMAT_*) of the compressed data.
 * \param UncompressedBuffer A buffer that receives the decompressed data.
 * \param UncompressedBufferSize The size, in bytes, of UncompressedBuffer.
 * \param CompressedBuffer The compressed data to decompress.
 * \param CompressedBufferSize The size, in bytes, of CompressedBuffer.
 * \param UncompressedChunkSize The chunk size used during compression (typically 4096).
 * \param FinalUncompressedSize Receives the size, in bytes, of the decompressed data.
 * \param WorkSpace An optional workspace buffer sized per RtlGetCompressionWorkSpaceSize.
 * \return NTSTATUS Successful or errant status.
 */
NTSTATUS
NTAPI
RtlDecompressBufferEx2(
    _In_ USHORT CompressionFormat,
    _Out_writes_bytes_to_(UncompressedBufferSize, *FinalUncompressedSize) PUCHAR UncompressedBuffer,
    _In_ ULONG UncompressedBufferSize,
    _In_reads_bytes_(CompressedBufferSize) PUCHAR CompressedBuffer,
    _In_ ULONG CompressedBufferSize,
    _In_ ULONG UncompressedChunkSize,
    _Out_ PULONG FinalUncompressedSize,
    _In_opt_ PVOID WorkSpace
);
#endif

NT_RTL_COMPRESS_API
/**
 * The RtlDecompressFragment routine decompresses a fragment of a compressed buffer beginning at the specified offset.
 *
 * \param CompressionFormat The compression format (COMPRESSION_FORMAT_*) of the compressed data.
 * \param UncompressedFragment A buffer that receives the decompressed fragment.
 * \param UncompressedFragmentSize The size, in bytes, of UncompressedFragment.
 * \param CompressedBuffer The compressed data to decompress.
 * \param CompressedBufferSize The size, in bytes, of CompressedBuffer.
 * \param FragmentOffset The offset, in bytes, into the uncompressed data at which the fragment begins.
 * \param FinalUncompressedSize Receives the size, in bytes, of the decompressed fragment.
 * \param WorkSpace A workspace buffer sized per RtlGetCompressionWorkSpaceSize.
 * \return NTSTATUS Successful or errant status.
 */
NTSTATUS
NTAPI
RtlDecompressFragment(
    _In_ USHORT CompressionFormat,
    _Out_writes_bytes_to_(UncompressedFragmentSize, *FinalUncompressedSize) PUCHAR UncompressedFragment,
    _In_ ULONG UncompressedFragmentSize,
    _In_reads_bytes_(CompressedBufferSize) PUCHAR CompressedBuffer,
    _In_ ULONG CompressedBufferSize,
    _In_range_(< , CompressedBufferSize) ULONG FragmentOffset,
    _Out_ PULONG FinalUncompressedSize,
    _In_ PVOID WorkSpace
);

#if (NTDDI_VERSION >= NTDDI_WINBLUE) || defined(_NT_STATIC_RTL_COMPRESS_)
NT_RTL_COMPRESS_API
/**
 * The RtlDecompressFragmentEx routine decompresses a fragment of a compressed buffer using the specified chunk size.
 *
 * \param CompressionFormat The compression format (COMPRESSION_FORMAT_*) of the compressed data.
 * \param UncompressedFragment A buffer that receives the decompressed fragment.
 * \param UncompressedFragmentSize The size, in bytes, of UncompressedFragment.
 * \param CompressedBuffer The compressed data to decompress.
 * \param CompressedBufferSize The size, in bytes, of CompressedBuffer.
 * \param FragmentOffset The offset, in bytes, into the uncompressed data at which the fragment begins.
 * \param UncompressedChunkSize The chunk size used during compression (typically 4096).
 * \param FinalUncompressedSize Receives the size, in bytes, of the decompressed fragment.
 * \param WorkSpace A workspace buffer sized per RtlGetCompressionWorkSpaceSize.
 * \return NTSTATUS Successful or errant status.
 */
NTSTATUS
NTAPI
RtlDecompressFragmentEx(
    _In_ USHORT CompressionFormat,
    _Out_writes_bytes_to_(UncompressedFragmentSize, *FinalUncompressedSize) PUCHAR UncompressedFragment,
    _In_ ULONG UncompressedFragmentSize,
    _In_reads_bytes_(CompressedBufferSize) PUCHAR CompressedBuffer,
    _In_ ULONG CompressedBufferSize,
    _In_range_(< , CompressedBufferSize) ULONG FragmentOffset,
    _In_ ULONG UncompressedChunkSize,
    _Out_ PULONG FinalUncompressedSize,
    _In_ PVOID WorkSpace
);
#endif

/**
 * The RtlDescribeChunk routine describes the next chunk within a compressed buffer and advances the buffer pointer past
 * it.
 *
 * \param CompressionFormat The compression format used to compress the buffer.
 * \param CompressedBuffer A pointer to a variable that points to the current position in the compressed buffer. On
 * return, the variable is advanced past the described chunk.
 * \param EndOfCompressedBufferPlus1 A pointer to the first byte beyond the end of the compressed buffer.
 * \param ChunkBuffer A pointer to a variable that receives a pointer to the chunk data.
 * \param ChunkSize A pointer to a variable that receives the size, in bytes, of the chunk.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlDescribeChunk(
    _In_ USHORT CompressionFormat,
    _Inout_ PUCHAR *CompressedBuffer,
    _In_ PUCHAR EndOfCompressedBufferPlus1,
    _Out_ PUCHAR *ChunkBuffer,
    _Out_ PULONG ChunkSize
);

/**
 * The RtlReserveChunk routine reserves space for a chunk within a compressed buffer.
 *
 * \param CompressionFormat The compression format used to compress the buffer.
 * \param CompressedBuffer A pointer to a variable that points to the current position in the compressed buffer. On
 * return, the variable is advanced past the reserved chunk.
 * \param EndOfCompressedBufferPlus1 A pointer to the first byte beyond the end of the compressed buffer.
 * \param ChunkBuffer A pointer to a variable that receives a pointer to the reserved chunk data.
 * \param ChunkSize The size, in bytes, of the chunk to reserve.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlReserveChunk(
    _In_ USHORT CompressionFormat,
    _Inout_ PUCHAR *CompressedBuffer,
    _In_ PUCHAR EndOfCompressedBufferPlus1,
    _Out_ PUCHAR *ChunkBuffer,
    _In_ ULONG ChunkSize
);

/**
 * The RtlDecompressChunks routine decompresses a set of compressed chunks described by a compressed data information
 * structure.
 *
 * \param UncompressedBuffer A buffer that receives the decompressed data.
 * \param UncompressedBufferSize The size, in bytes, of the uncompressed buffer.
 * \param CompressedBuffer A pointer to the compressed data.
 * \param CompressedBufferSize The size, in bytes, of the compressed buffer.
 * \param CompressedTail A pointer to the compressed tail data.
 * \param CompressedTailSize The size, in bytes, of the compressed tail.
 * \param CompressedDataInfo A pointer to the structure that describes the compressed chunks.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlDecompressChunks(
    _Out_writes_bytes_(UncompressedBufferSize) PUCHAR UncompressedBuffer,
    _In_ ULONG UncompressedBufferSize,
    _In_reads_bytes_(CompressedBufferSize) PUCHAR CompressedBuffer,
    _In_ ULONG CompressedBufferSize,
    _In_reads_bytes_(CompressedTailSize) PUCHAR CompressedTail,
    _In_ ULONG CompressedTailSize,
    _In_ PCOMPRESSED_DATA_INFO CompressedDataInfo
);

/**
 * The RtlCompressChunks routine compresses a buffer as a series of chunks, recording per-chunk metadata.
 *
 * \param UncompressedBuffer The data to compress.
 * \param UncompressedBufferSize The size, in bytes, of UncompressedBuffer.
 * \param CompressedBuffer A buffer that receives the compressed data.
 * \param CompressedBufferSize The size, in bytes, of CompressedBuffer.
 * \param CompressedDataInfo Receives per-chunk compressed data information.
 * \param CompressedDataInfoLength The size, in bytes, of CompressedDataInfo.
 * \param WorkSpace A workspace buffer sized per RtlGetCompressionWorkSpaceSize.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlCompressChunks(
    _In_reads_bytes_(UncompressedBufferSize) PUCHAR UncompressedBuffer,
    _In_ ULONG UncompressedBufferSize,
    _Out_writes_bytes_(CompressedBufferSize) PUCHAR CompressedBuffer,
    _In_range_(>= , (UncompressedBufferSize - (UncompressedBufferSize / 16))) ULONG CompressedBufferSize,
    _Inout_updates_bytes_(CompressedDataInfoLength) PCOMPRESSED_DATA_INFO CompressedDataInfo,
    _In_range_(> , sizeof(COMPRESSED_DATA_INFO)) ULONG CompressedDataInfoLength,
    _In_ PVOID WorkSpace
);

EXTERN_C_END
