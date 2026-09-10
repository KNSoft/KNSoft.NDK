#pragma once

#include "../../../NT/MinDef.h"

#include <bcrypt.h>
#include <ncrypt.h>
#include <wincrypt.h>

EXTERN_C_START

#define FVE_TPM_INFO_VERSION_1 1

// private
typedef struct _FVE_UEFI_VARIABLE_INFO
{
    PBYTE UEFIVariableValue;
    ULONG UEFIVariableSizeBytes;
} FVE_UEFI_VARIABLE_INFO, *PFVE_UEFI_VARIABLE_INFO;

// private
typedef struct _FVE_TPM_PCR7_INFO
{
    PFVE_UEFI_VARIABLE_INFO PlatformKeyVariableInfo;
    PFVE_UEFI_VARIABLE_INFO KekDatabaseVariableInfo;
    PFVE_UEFI_VARIABLE_INFO AllowedDatabaseVariableInfo;
    PFVE_UEFI_VARIABLE_INFO ForbiddenDatabaseVariableInfo;
    PBYTE OsLoaderAuthoritySignature;
    ULONG OsLoaderAuthoritySignatureSizeBytes;
    ULONG CountSeparatorEvents;
} FVE_TPM_PCR7_INFO, *PFVE_TPM_PCR7_INFO;

// private
typedef struct _FVE_TPM_PCR4_INFO
{
    WCHAR BootMgrFilePath[MAX_PATH];
} FVE_TPM_PCR4_INFO, *PFVE_TPM_PCR4_INFO;

// private
typedef struct _FVE_TPM_PROTECTOR_INFO
{
    UINT32 TpmPcrIndex;
    union
    {
        PFVE_TPM_PCR7_INFO FveTpmPcr7Info;
        PFVE_TPM_PCR4_INFO FveTpmPcr4Info;
    } PredictiveSealInfo;
} FVE_TPM_PROTECTOR_INFO, *PFVE_TPM_PROTECTOR_INFO;

// private
typedef struct _FVE_TPM_STATE_
{
    PVOID TpmContext;
    ULONG FveTpmProtectorInfoCount;
    PFVE_TPM_PROTECTOR_INFO FveTpmProtectorInfo;
} FVE_TPM_STATE, *PFVE_TPM_STATE;

// private
typedef struct _FVE_TPM_INFO_
{
    ULONG FveTpmInfoVersion;
    PFVE_TPM_STATE TpmStateInfo;
} FVE_TPM_INFO, *PFVE_TPM_INFO;

// private
typedef HRESULT (WINAPI *PFVE_TPM_API_CALLBACK)(
    PVOID hContext,
    UINT32 cbCmd,
    const BYTE *pabCmd,
    PUINT32 pcbResult,
    PBYTE pabResult
    );

// private
typedef enum _FVE_DEVICE_TYPE
{
    FVE_DEVICE_UNKNOWN = -1,
    FVE_DEVICE_UNSUPPORTED = 0,
    FVE_DEVICE_VOLUME,
    FVE_DEVICE_CSV_VOLUME,
    FVE_DEVICE_MAX
} FVE_DEVICE_TYPE, *PFVE_DEVICE_TYPE;

// private
typedef enum _FVE_INTERFACE_TYPE
{
    FVE_INTERFACE_UNKNOWN = -1,
    FVE_INTERFACE_SEI = 0,
    FVE_INTERFACE_SYS,
    FVE_INTERFACE_HEI,
    FVE_INTERFACE_MAX
} FVE_INTERFACE_TYPE, *PFVE_INTERFACE_TYPE;

// private
typedef enum _FVE_HANDLE_TYPE
{
    FVE_HANDLE_UNKNOWN = -1,
    FVE_HANDLE_FVE = 0,
    FVE_HANDLE_NONFVE,
    FVE_HANDLE_MAX
} FVE_HANDLE_TYPE, *PFVE_HANDLE_TYPE;

// private
typedef enum _FVE_SCENARIO_TYPE
{
    FVE_SCENARIO_UNKNOWN = -1,
    FVE_SCENARIO_DEFAULT = 0,
    FVE_SCENARIO_KEY_ROLL,
    FVE_SCENARIO_BOOT_COMPONENT_UPDATE,
    FVE_SCENARIO_UNDEFINED_SKIP_CHECKS,
    FVE_SCENARIO_POLICY_BASED_ENABLEMENT,
    FVE_SCENARIO_PUSH_BUTTON_RESET,
    FVE_SCENARIO_UPGRADE,
    FVE_SCENARIO_DEVICE_LOCKOUT_LOCK,
    FVE_SCENARIO_DEVICE_LOCKOUT_RECOVER,
    FVE_SCENARIO_PPF_PREDICTIONS_UPDATED,
    FVE_SCENARIO_DEVICE_ENCRYPTION,
    FVE_SCENARIO_TMCORE_PROVISIONING
} FVE_SCENARIO_TYPE, *PFVE_SCENARIO_TYPE;

// private
typedef enum _FVE_PROTECTOR_TYPE
{
    FveKeyProtTypeUnknown = 0,
    FveKeyProtTypeTpm,
    FveKeyProtTypeKey,
    FveKeyProtTypePassword,
    FveKeyProtTypeTpmAndPin,
    FveKeyProtTypeTpmAndKey,
    FveKeyProtTypeTpmAndPinAndKey,
    FveKeyProtTypeCertificate,
    FveKeyProtTypePassPhrase,
    FveKeyProtTypeTpmAndCertificate,
    FveKeyProtTypeDpapiNg
} FVE_PROTECTOR_TYPE, *PFVE_PROTECTOR_TYPE;

// private
typedef enum _FVE_METHOD
{
    FveMethodWcos = -2,
    FveMethodUnknown = -1,
    FveMethodNone = 0,
    FveMethodAesWithDiffuser = 1,
    FveMethodAes = 3,
    FveMethodEdrive = 5,
    FveMethodXtsAes = 6
} FVE_METHOD, *PFVE_METHOD;

// private
typedef enum _FVE_METHOD_STRENGTH
{
    FveMethodStrengthNone = 0,
    FveMethodStrength128,
    FveMethodStrength256
} FVE_METHOD_STRENGTH, *PFVE_METHOD_STRENGTH;

// private
typedef enum _FVE_LEGACY_METHOD
{
    FveLegacyMethodWcos = -2,
    FveLegacyMethodUnknown = -1,
    FveLegacyMethodNone = 0,
    FveLegacyMethodAes128WithDiffuser,
    FveLegacyMethodAes256WithDiffuser,
    FveLegacyMethodAes128,
    FveLegacyMethodAes256,
    FveLegacyMethodHardware,
    FveLegacyMethodXtsAes128,
    FveLegacyMethodXtsAes256
} FVE_LEGACY_METHOD, *PFVE_LEGACY_METHOD;

// private
typedef enum _FVE_QUERY_TYPE
{
    FVE_QUERY_UNKNOWN = 0,
    FVE_QUERY_UNSUPPORTED,
    FVE_QUERY_VOLUMES,
    FVE_QUERY_CSV_VOLUMES,
    FVE_QUERY_DE_NOT_INITIALIZED,
    FVE_QUERY_WCOS_SECURITY_INFO,
    FVE_QUERY_BOOT_INTEGRITY_INFO,
    FVE_QUERY_CONSIDER_TPM_PROTECTOR_VERSION_UPGRADE,
    FVE_QUERY_TPM_PROTECTOR_VERSION,
    FVE_QUERY_TPM_PROTECTOR_CONTAINS_SECURE_BOOT_BINDING,
    FVE_QUERY_CHECK_SECURE_BOOT_FOR_BITLOCKER,
    FVE_QUERY_TPM_PROTECTOR_BINDINGS_COUNT,
    FVE_QUERY_TPM_PROTECTOR_BINDING_CENSUS,
    FVE_QUERY_DEFAULT_PCR_PROFILE,
    FVE_QUERY_PREDICTION_INSTANCE_MAPPING,
    FVE_QUERY_MAX
} FVE_QUERY_TYPE, *PFVE_QUERY_TYPE;

// private
typedef enum _FVE_CONTROL_TYPE
{
    FVE_CONTROL_UNKNOWN = 0,
    FVE_CONTROL_PROTECT_WITH_EK,
    FVE_CONTROL_CLEAR_KEYS_FROM_KEYRING,
    FVE_CONTROL_SET_DEFAULT_PCR_PROFILE,
    FVE_CONTROL_TMCORE_PROVISION,
    FVE_CONTROL_SET_PREDICTION_INSTANCE_MAPPING,
    FVE_CONTROL_MAX
} FVE_CONTROL_TYPE, *PFVE_CONTROL_TYPE;

// private
typedef enum _FVE_SECUREBOOT_BINDING_STATE
{
    FVE_SECUREBOOT_BINDING_UNKNOWN = -1,
    FVE_SECUREBOOT_BINDING_NOT_POSSIBLE = 0,
    FVE_SECUREBOOT_BINDING_DISABLED_BY_POLICY,
    FVE_SECUREBOOT_BINDING_POSSIBLE,
    FVE_SECUREBOOT_BINDING_BOUND
} FVE_SECUREBOOT_BINDING_STATE, *PFVE_SECUREBOOT_BINDING_STATE;

// private
typedef enum _FVE_WIPING_STATE
{
    FVE_WIPING_STATE_UNSPECIFIED = 0,
    FVE_WIPING_STATE_INACTIVE,
    FVE_WIPING_STATE_PENDING,
    FVE_WIPING_STATE_STOPPED,
    FVE_WIPING_STATE_INPROGRESS
} FVE_WIPING_STATE, *PFVE_WIPING_STATE;

// private
typedef struct _ADA_GP_OPTIONS
{
    BOOL BackupEnabled;
    BOOL BackupKeyPackage;
    BOOL BackupRequired;
} ADA_GP_OPTIONS, *PADA_GP_OPTIONS;

#define FVE_EXTERNAL_DATA_ENTRY_VERSION_1 1
#define FVE_EXTERNAL_DATA_ENTRY_DESCRIPTION_LENGTH 16

#pragma pack(push, 1)

// private
typedef struct _FVE_EXTERNAL_DATA_ENTRY_INFO_V1
{
    USHORT StructureSizeBytes;
    USHORT StructureVersion;
    GUID EntryTypeId;
    GUID EntryId;
    WCHAR EntryLabel[FVE_EXTERNAL_DATA_ENTRY_DESCRIPTION_LENGTH];
    FILETIME DateTimeCreated;
} FVE_EXTERNAL_DATA_ENTRY_INFO_V1, *PFVE_EXTERNAL_DATA_ENTRY_INFO_V1;

typedef const FVE_EXTERNAL_DATA_ENTRY_INFO_V1 *PCFVE_EXTERNAL_DATA_ENTRY_INFO_V1;

// private
typedef struct _FVE_EXTERNAL_DATA_ENTRY_SELECT_V1
{
    USHORT StructureSizeBytes;
    USHORT StructureVersion;
    ULONG SelectFlags;
    GUID EntryTypeId;
    GUID EntryId;
} FVE_EXTERNAL_DATA_ENTRY_SELECT_V1, *PFVE_EXTERNAL_DATA_ENTRY_SELECT_V1;

typedef const FVE_EXTERNAL_DATA_ENTRY_SELECT_V1 *PCFVE_EXTERNAL_DATA_ENTRY_SELECT_V1;

#pragma pack(pop)

// private
typedef struct _NGSCB_HSTI_RESULTS NGSCB_HSTI_RESULTS, *PNGSCB_HSTI_RESULTS;

// private
typedef struct _NGSCB_NAME_VALUE_COLLECTION NGSCB_NAME_VALUE_COLLECTION, *PNGSCB_NAME_VALUE_COLLECTION;

// private
typedef struct _NGSCB_HSTI_PARSING_STATUS NGSCB_HSTI_PARSING_STATUS, *PNGSCB_HSTI_PARSING_STATUS;

// private
typedef struct PPF_PREDICTIONS_UPDATED_CONTEXT PPF_PREDICTIONS_UPDATED_CONTEXT, *PPPF_PREDICTIONS_UPDATED_CONTEXT;

#define FVE_STATUS_VERSION_1 1
#define FVE_STATUS_VERSION_2 2
#define FVE_STATUS_VERSION_3 3
#define FVE_STATUS_VERSION_4 4
#define FVE_STATUS_VERSION_5 5
#define FVE_STATUS_VERSION_6 6
#define FVE_STATUS_VERSION_7 7
#define FVE_STATUS_VERSION_8 8
#define FVE_STATUS_VERSION_9 9

#define FVE_STATUS_FLAG_INITIALIZED 0x00000001UL
#define FVE_STATUS_FLAG_FULLY_DECRYPTED 0x00000004UL
#define FVE_STATUS_FLAG_FULLY_ENCRYPTED 0x00000008UL
#define FVE_STATUS_FLAG_DECRYPTION_IN_PROGRESS 0x00000010UL
#define FVE_STATUS_FLAG_ENCRYPTION_IN_PROGRESS 0x00000020UL
#define FVE_STATUS_FLAG_CONVERSION_PAUSED_MASK 0x000000C0UL
#define FVE_STATUS_FLAG_NON_TPM_PROTECTOR 0x00000100UL
#define FVE_STATUS_FLAG_TPM_PROTECTOR 0x00000200UL
#define FVE_STATUS_FLAG_CLEAR_KEY 0x00000400UL
#define FVE_STATUS_FLAG_LOCKED 0x00000800UL
#define FVE_STATUS_FLAG_PROTECTION_ACTIVE 0x00001000UL
#define FVE_STATUS_FLAG_OS_VOLUME 0x00004000UL
#define FVE_STATUS_FLAG_EXTERNAL_KEY_PROTECTOR 0x00020000UL
#define FVE_STATUS_FLAG_RECOVERY_PASSWORD_PROTECTOR 0x00040000UL
#define FVE_STATUS_FLAG_TPM_PIN_PROTECTOR 0x00080000UL
#define FVE_STATUS_FLAG_TPM_STARTUP_KEY_PROTECTOR 0x00100000UL
#define FVE_STATUS_FLAG_PASSPHRASE_PROTECTOR 0x00200000UL
#define FVE_STATUS_FLAG_REMOVABLE_DATA_VOLUME 0x00400000UL
#define FVE_STATUS_FLAG_CERTIFICATE_PROTECTOR 0x00800000UL
#define FVE_STATUS_FLAG_DATA_ONLY_ENCRYPTION 0x01000000UL
#define FVE_STATUS_FLAG_INITIALIZATION_UNKNOWN100 0x10000000UL

#define FVE_CONVERSION_FLAG_DATA_ONLY 0x00000001UL
#define FVE_INITIALIZATION_UNKNOWN100 0x00000100UL

// private
typedef struct _FVE_STATUS_V1
{
    ULONG StructureSize;
    ULONG StructureVersion;
    ULONG Flags;
    DOUBLE ConvertedPercent;
    HRESULT LastConvertStatus;
} FVE_STATUS_V1, *PFVE_STATUS_V1;

typedef const FVE_STATUS_V1 *PCFVE_STATUS_V1;

C_ASSERT(sizeof(FVE_STATUS_V1) == 32);

// private
typedef struct _FVE_STATUS_V2
{
    ULONG StructureSize;
    ULONG StructureVersion;
    USHORT FveVersion;
    ULONG Flags;
    DOUBLE ConvertedPercent;
    HRESULT LastConvertStatus;
} FVE_STATUS_V2, *PFVE_STATUS_V2;

typedef const FVE_STATUS_V2 *PCFVE_STATUS_V2;

// private
typedef struct _FVE_STATUS_V3
{
    ULONG StructureSize;
    ULONG StructureVersion;
    USHORT FveVersion;
    ULONG Flags;
    DOUBLE ConvertedPercent;
    HRESULT LastConvertStatus;
    LONGLONG VolArriveTime;
} FVE_STATUS_V3, *PFVE_STATUS_V3;

typedef const FVE_STATUS_V3 *PCFVE_STATUS_V3;

// private
typedef struct _FVE_STATUS_V4
{
    ULONG StructureSize;
    ULONG StructureVersion;
    USHORT FveVersion;
    ULONG Flags;
    DOUBLE ConvertedPercent;
    HRESULT LastConvertStatus;
    LONGLONG VolArriveTime;
    DOUBLE WipedPercent;
    ULONG WipeState;
    ULONG WipeCount;
    ULONGLONG ExtendedFlags;
} FVE_STATUS_V4, *PFVE_STATUS_V4;

typedef const FVE_STATUS_V4 *PCFVE_STATUS_V4;

#pragma warning(push)
#pragma warning(disable: 4201 4214)

// private
typedef struct _FVE_STATUS_V5
{
    ULONG StructureSize;
    ULONG StructureVersion;
    USHORT FveVersion;
    ULONG Flags;
    DOUBLE ConvertedPercent;
    HRESULT LastConvertStatus;
    LONGLONG VolArriveTime;
    DOUBLE WipedPercent;
    ULONG WipeState;
    ULONG WipeCount;
    ULONGLONG ExtendedFlags;
    ULONGLONG WimBootHashedSizeRequired;
    ULONGLONG WimBootHashedSizeActual;
    union
    {
        ULONGLONG ExtendedFlags2;
        struct
        {
            BOOLEAN WimBootVolume : 1;
            BOOLEAN WimBootHashCompleted : 1;
        };
    };
} FVE_STATUS_V5, *PFVE_STATUS_V5;

typedef const FVE_STATUS_V5 *PCFVE_STATUS_V5;

// private
typedef struct _FVE_STATUS_V6
{
    ULONG StructureSize;
    ULONG StructureVersion;
    USHORT FveVersion;
    ULONG Flags;
    DOUBLE ConvertedPercent;
    HRESULT LastConvertStatus;
    LONGLONG VolArriveTime;
    DOUBLE WipedPercent;
    ULONG WipeState;
    ULONG WipeCount;
    ULONGLONG ExtendedFlags;
    ULONGLONG WimBootHashedSizeRequired;
    ULONGLONG WimBootHashedSizeActual;
    union
    {
        ULONGLONG ExtendedFlags2;
        struct
        {
            BOOLEAN WimBootVolume : 1;
            BOOLEAN WimBootHashCompleted : 1;
            BOOLEAN IceIsUsedForFve : 1;
            BOOLEAN IsEfiEsp : 1;
            BOOLEAN IsRecovery : 1;
            BOOLEAN WcosDePolicy : 1;
            BOOLEAN WcosOsData : 1;
            BOOLEAN WcosPreInstalled : 1;
            BOOLEAN WcosUserData : 1;
            BOOLEAN WcosMainOs : 1;
            BOOLEAN WcosEfiEsp : 1;
            BOOLEAN WcosBsp : 1;
        };
    };
    ULONG WcosOsMainProtectLevel;
    ULONG WcosOsDataProtectLevel;
    ULONG WcosPreInstalledProtectLevel;
    ULONG WcosUserDataProtectLevel;
} FVE_STATUS_V6, *PFVE_STATUS_V6;

typedef const FVE_STATUS_V6 *PCFVE_STATUS_V6;

// private
typedef struct _FVE_STATUS_V7
{
    ULONG StructureSize;
    ULONG StructureVersion;
    USHORT FveVersion;
    ULONG Flags;
    DOUBLE ConvertedPercent;
    HRESULT LastConvertStatus;
    LONGLONG VolArriveTime;
    DOUBLE WipedPercent;
    ULONG WipeState;
    ULONG WipeCount;
    ULONGLONG ExtendedFlags;
    ULONGLONG WimBootHashedSizeRequired;
    ULONGLONG WimBootHashedSizeActual;
    union
    {
        ULONGLONG ExtendedFlags2;
        struct
        {
            BOOLEAN WimBootVolume : 1;
            BOOLEAN WimBootHashCompleted : 1;
            BOOLEAN IceIsUsedForFve : 1;
            BOOLEAN IsEfiEsp : 1;
            BOOLEAN IsRecovery : 1;
            BOOLEAN WcosDePolicy : 1;
            BOOLEAN WcosOsData : 1;
            BOOLEAN WcosPreInstalled : 1;
            BOOLEAN WcosUserData : 1;
            BOOLEAN WcosMainOs : 1;
            BOOLEAN WcosEfiEsp : 1;
            BOOLEAN WcosBsp : 1;
            BOOLEAN WcosWsp : 1;
        };
    };
    ULONG WcosOsMainProtectLevel;
    ULONG WcosOsDataProtectLevel;
    ULONG WcosPreInstalledProtectLevel;
    ULONG WcosUserDataProtectLevel;
    ULONG WcosBspProtectLevel;
    ULONG WcosWspProtectLevel;
} FVE_STATUS_V7, *PFVE_STATUS_V7;

typedef const FVE_STATUS_V7 *PCFVE_STATUS_V7;

// private
typedef struct _FVE_STATUS_V8
{
    ULONG StructureSize;
    ULONG StructureVersion;
    USHORT FveVersion;
    ULONG Flags;
    DOUBLE ConvertedPercent;
    HRESULT LastConvertStatus;
    LONGLONG VolArriveTime;
    DOUBLE WipedPercent;
    ULONG WipeState;
    ULONG WipeCount;
    ULONGLONG ExtendedFlags;
    ULONGLONG WimBootHashedSizeRequired;
    ULONGLONG WimBootHashedSizeActual;
    union
    {
        ULONGLONG ExtendedFlags2;
        struct
        {
            BOOLEAN WimBootVolume : 1;
            BOOLEAN WimBootHashCompleted : 1;
            BOOLEAN IceIsUsedForFve : 1;
            BOOLEAN IsEfiEsp : 1;
            BOOLEAN IsRecovery : 1;
            BOOLEAN WcosDePolicy : 1;
            BOOLEAN WcosOsData : 1;
            BOOLEAN WcosPreInstalled : 1;
            BOOLEAN WcosUserData : 1;
            BOOLEAN WcosMainOs : 1;
            BOOLEAN WcosEfiEsp : 1;
            BOOLEAN WcosBsp : 1;
            BOOLEAN WcosWsp : 1;
            BOOLEAN WcosDpp : 1;
        };
    };
    ULONG WcosOsMainProtectLevel;
    ULONG WcosOsDataProtectLevel;
    ULONG WcosPreInstalledProtectLevel;
    ULONG WcosUserDataProtectLevel;
    ULONG WcosBspProtectLevel;
    ULONG WcosWspProtectLevel;
    ULONG WcosDppProtectLevel;
} FVE_STATUS_V8, *PFVE_STATUS_V8;

typedef const FVE_STATUS_V8 *PCFVE_STATUS_V8;

// private
typedef struct _FVE_STATUS_V9
{
    ULONG StructureSize;
    ULONG StructureVersion;
    USHORT FveVersion;
    ULONG Flags;
    DOUBLE ConvertedPercent;
    HRESULT LastConvertStatus;
    LONGLONG VolArriveTime;
    DOUBLE WipedPercent;
    ULONG WipeState;
    ULONG WipeCount;
    ULONGLONG ExtendedFlags;
    ULONGLONG WimBootHashedSizeRequired;
    ULONGLONG WimBootHashedSizeActual;
    union
    {
        ULONGLONG ExtendedFlags2;
        struct
        {
            BOOLEAN WimBootVolume : 1;
            BOOLEAN WimBootHashCompleted : 1;
            BOOLEAN IceIsUsedForFve : 1;
            BOOLEAN IsEfiEsp : 1;
            BOOLEAN IsRecovery : 1;
            BOOLEAN WcosDePolicy : 1;
            BOOLEAN WcosOsData : 1;
            BOOLEAN WcosPreInstalled : 1;
            BOOLEAN WcosUserData : 1;
            BOOLEAN WcosMainOs : 1;
            BOOLEAN WcosEfiEsp : 1;
            BOOLEAN WcosBsp : 1;
            BOOLEAN WcosWsp : 1;
            BOOLEAN WcosDpp : 1;
            BOOLEAN WcosServicingMetadata : 1;
            BOOLEAN WcosServicingFiles : 1;
            BOOLEAN WcosServicingReserve : 1;
            BOOLEAN IsOnRdvPolicyExclusionList : 1;
            BOOLEAN IsIceDirectKeyTypeSupported : 1;
            BOOLEAN IsIcePlatformWrappedKeyTypeSupported : 1;
            BOOLEAN IsIcePlutonWrappedKeyTypeSupported : 1;
            BOOLEAN IsIceDirectKeyTypeUsed : 1;
            BOOLEAN IsIcePlatformWrappedKeyTypeUsed : 1;
            BOOLEAN IsIcePlutonWrappedKeyTypeUsed : 1;
            BOOLEAN IceTypeIsUfs : 1;
            BOOLEAN IceTypeIsNvme : 1;
        };
    };
    ULONG WcosOsMainProtectLevel;
    ULONG WcosOsDataProtectLevel;
    ULONG WcosPreInstalledProtectLevel;
    ULONG WcosUserDataProtectLevel;
    ULONG WcosBspProtectLevel;
    ULONG WcosWspProtectLevel;
    ULONG WcosDppProtectLevel;
    ULONG WcosServicingMetadataProtectLevel;
    ULONG WcosServicingFilesProtectLevel;
    ULONG WcosServicingReserveProtectLevel;
} FVE_STATUS_V9, *PFVE_STATUS_V9;

typedef const FVE_STATUS_V9 *PCFVE_STATUS_V9;

#pragma warning(pop)

C_ASSERT(sizeof(FVE_STATUS_V9) == 128);

#define FVE_FIND_VERSION_1 1

// private
typedef struct _FVE_FIND_DATA_V1
{
    ULONG FveFindVersion;
    FVE_DEVICE_TYPE DevType;
} FVE_FIND_DATA_V1, *PFVE_FIND_DATA_V1;

typedef const FVE_FIND_DATA_V1 *PCFVE_FIND_DATA_V1;

#define FVE_TPM_CAPS_VERSION_1 1
#define FVE_TPM_CAPS_VERSION_2 2

// private
typedef struct _FVE_TPM_CAPS
{
    ULONG StructureSize;
    ULONG StructureVersion;
    HRESULT TpmStatus;
    ULONG Flags;
} FVE_TPM_CAPS, *PFVE_TPM_CAPS;

typedef const FVE_TPM_CAPS *PCFVE_TPM_CAPS;

// private
typedef struct _FVE_TPM_CAPS_TPM_PRESENCE
{
    ULONG StructureSize;
    ULONG StructureVersion;
    HRESULT NotUsed;
    ULONG NotUsed2;
    BOOL TpmPresent;
} FVE_TPM_CAPS_TPM_PRESENCE, *PFVE_TPM_CAPS_TPM_PRESENCE;

typedef const FVE_TPM_CAPS_TPM_PRESENCE *PCFVE_TPM_CAPS_TPM_PRESENCE;

#define FVE_AUTH_ELEMENT_VERSION_1 1
#define FVE_AUTH_ELEMENT_FLAG_UNKNOWN1 0x00000001UL
#define FVE_AUTH_PASSPHRASE_MAX_LENGTH 256

// private
typedef enum _FVE_AUTH_ELEMENT_TYPE
{
    FveAuthElementTypeUnknown = 0,
    FveAuthElementTypeRecoveryPassword,
    FveAuthElementTypePin,
    FveAuthElementTypeTpm,
    FveAuthElementTypeExternalKey,
    FveAuthElementTypePublicKey,
    FveAuthElementTypeUnknown6,
    FveAuthElementTypeUnknown7,
    FveAuthElementTypePassPhrase,
    FveAuthElementTypeClearKey
} FVE_AUTH_ELEMENT_TYPE, *PFVE_AUTH_ELEMENT_TYPE;

// private
typedef struct _FVE_AUTH_RECOVERY_PASSWORD
{
    USHORT Block[8];
} FVE_AUTH_RECOVERY_PASSWORD, *PFVE_AUTH_RECOVERY_PASSWORD;

// private
typedef struct _FVE_AUTH_PIN
{
    BYTE HashedPin[32];
} FVE_AUTH_PIN, *PFVE_AUTH_PIN;

// private
typedef struct _FVE_AUTH_TPM
{
    ULONG PcrBitmap;
    GUID PcrBitmapScenarioId;
} FVE_AUTH_TPM, *PFVE_AUTH_TPM;

// private
typedef struct _FVE_AUTH_PREDICTED_TPM_INFO
{
    PFVE_TPM_STATE FveTpmState;
} FVE_AUTH_PREDICTED_TPM_INFO, *PFVE_AUTH_PREDICTED_TPM_INFO;

typedef const FVE_AUTH_PREDICTED_TPM_INFO *PCFVE_AUTH_PREDICTED_TPM_INFO;

// private
typedef struct _FVE_AUTH_EXTERNAL_KEY
{
    BYTE Key[32];
} FVE_AUTH_EXTERNAL_KEY, *PFVE_AUTH_EXTERNAL_KEY;

// private
typedef struct _FVE_AUTH_PUBLIC_KEY
{
    BCRYPT_KEY_HANDLE Handle;
    ULONG BlobSize;
    PBYTE Blob;
} FVE_AUTH_PUBLIC_KEY, *PFVE_AUTH_PUBLIC_KEY;

// private
typedef struct _FVE_AUTH_PRIVATE_KEY
{
    NCRYPT_KEY_HANDLE KspKeyHandle;
    HCRYPTPROV CspProviderHandle;
    HCRYPTKEY CspKeyHandle;
    DWORD KeySpec;
} FVE_AUTH_PRIVATE_KEY, *PFVE_AUTH_PRIVATE_KEY;

// private
typedef struct _FVE_AUTH_INFO_PUBLIC_KEY
{
    ULONG ExportedPublicKeySize;
    ULONG ExportedPublicKeyOffset;
    ULONG BlobSize;
    ULONG BlobOffset;
} FVE_AUTH_INFO_PUBLIC_KEY, *PFVE_AUTH_INFO_PUBLIC_KEY;

// private
typedef struct _FVE_AUTH_PASSPHRASE
{
    WCHAR ClearPassPhrase[FVE_AUTH_PASSPHRASE_MAX_LENGTH + 1];
    BYTE HashedPassPhrase[32];
    BYTE Salt[16];
} FVE_AUTH_PASSPHRASE, *PFVE_AUTH_PASSPHRASE;

// private
typedef struct _FVE_AUTH_INFO_CLEAR_KEY
{
    UCHAR Count;
} FVE_AUTH_INFO_CLEAR_KEY, *PFVE_AUTH_INFO_CLEAR_KEY;

// private
typedef struct _FVE_AUTH_DPAPI_NG
{
    USHORT DpapiNgFlags;
    USHORT DescriptorLength;
    WCHAR DpapiNgDescriptor[ANYSIZE_ARRAY];
} FVE_AUTH_DPAPI_NG, *PFVE_AUTH_DPAPI_NG;

// private
typedef struct _FVE_AUTH_NETWORK_SERVER_INFO
{
    WCHAR LocalIPAddress[65];
    ULONG ServerIPAddressesCount;
    ULONG ServerIPAddressesSize;
    WCHAR ServerIPAddresses[ANYSIZE_ARRAY][65];
} FVE_AUTH_NETWORK_SERVER_INFO, *PFVE_AUTH_NETWORK_SERVER_INFO;

typedef const FVE_AUTH_NETWORK_SERVER_INFO *PCFVE_AUTH_NETWORK_SERVER_INFO;

// private
typedef struct _FVE_AUTH_ELEMENT
{
    ULONG StructureSize;
    ULONG StructureVersion;
    ULONG ElementFlags;
    FVE_AUTH_ELEMENT_TYPE ElementType;
    union
    {
        BYTE Nothing[ANYSIZE_ARRAY];
        FVE_AUTH_RECOVERY_PASSWORD RecoveryPassword;
        FVE_AUTH_PIN Pin;
        FVE_AUTH_TPM Tpm;
        FVE_AUTH_EXTERNAL_KEY ExternalKey;
        FVE_AUTH_PUBLIC_KEY PublicKey;
        FVE_AUTH_PRIVATE_KEY PrivateKey;
        FVE_AUTH_INFO_PUBLIC_KEY PublicKeyInfo;
        FVE_AUTH_PASSPHRASE PassPhrase;
        FVE_AUTH_INFO_CLEAR_KEY ClearKeyInfo;
        FVE_AUTH_DPAPI_NG DpapiNgInfo;
        FVE_AUTH_NETWORK_SERVER_INFO NetworkServerInfo;
        FVE_AUTH_PREDICTED_TPM_INFO PredictedTpmInfo;
    } Data;
} FVE_AUTH_ELEMENT, *PFVE_AUTH_ELEMENT;

typedef const FVE_AUTH_ELEMENT *PCFVE_AUTH_ELEMENT;

#ifdef _WIN64
C_ASSERT(sizeof(FVE_AUTH_ELEMENT) == 584);
#else
C_ASSERT(sizeof(FVE_AUTH_ELEMENT) == 580);
#endif

#define FVE_AUTH_INFORMATION_VERSION_1 1

#define FVE_AUTH_INFORMATION_QUERY_UNKNOWN1 0x00000001UL
#define FVE_AUTH_INFORMATION_QUERY_UNKNOWN2 0x00000002UL
#define FVE_AUTH_INFORMATION_QUERY_UNKNOWN4 0x00000004UL

#define FVE_AUTH_INFORMATION_FLAG_CLEAR_KEY 0x00010000UL
#define FVE_AUTH_INFORMATION_FLAG_TPM 0x00020000UL
#define FVE_AUTH_INFORMATION_FLAG_EXTERNAL_KEY 0x00040000UL
#define FVE_AUTH_INFORMATION_FLAG_RECOVERY_PASSWORD 0x00080000UL
#define FVE_AUTH_INFORMATION_FLAG_TPM_AND_PIN 0x00120000UL
#define FVE_AUTH_INFORMATION_FLAG_TPM_AND_STARTUP_KEY 0x00060000UL
#define FVE_AUTH_INFORMATION_FLAG_TPM_PIN_AND_STARTUP_KEY 0x00160000UL
#define FVE_AUTH_INFORMATION_FLAG_CERTIFICATE 0x00200000UL
#define FVE_AUTH_INFORMATION_FLAG_PASSPHRASE 0x00800000UL
#define FVE_AUTH_INFORMATION_FLAG_TPM_AND_CERTIFICATE 0x00220000UL
#define FVE_AUTH_INFORMATION_FLAG_DPAPI_NG 0x01000000UL
#define FVE_AUTH_INFORMATION_PROTECTOR_MASK 0x03FE0000UL

// private
typedef struct _FVE_AUTH_INFORMATION
{
    ULONG StructureSize;
    ULONG StructureVersion;
    ULONG AuthFlags;
    ULONG ElementsCount;
    PFVE_AUTH_ELEMENT *Elements;
    PCWSTR Description;
    FILETIME CreationTime;
    GUID Identifier;
} FVE_AUTH_INFORMATION, *PFVE_AUTH_INFORMATION;

typedef const FVE_AUTH_INFORMATION *PCFVE_AUTH_INFORMATION;

#ifdef _WIN64
C_ASSERT(sizeof(FVE_AUTH_INFORMATION) == 56);
#else
C_ASSERT(sizeof(FVE_AUTH_INFORMATION) == 48);
#endif

#define FVE_DE_SUPPORT_VERSION_1 1

// private
typedef struct _FVE_DE_SUPPORT
{
    ULONG StructureSize;
    ULONG StructureVersion;
    ULONG QueryFlags;
    HRESULT SupportStatus;
    ULONG SupportFlags;
} FVE_DE_SUPPORT, *PFVE_DE_SUPPORT;

typedef const FVE_DE_SUPPORT *PCFVE_DE_SUPPORT;

#define FVE_EDRIVE_METHOD_CCH 256

#define FVEAPI DECLSPEC_IMPORT

// rev
FVEAPI
HRESULT
WINAPI
InternalFveIsVolumeEncrypted(
    _In_ HANDLE FveVolumeHandle
    );

// rev
FVEAPI
HRESULT
WINAPI
NgscbCheckDmaSecurity(
    _Out_ PBOOLEAN IsDmaSecure,
    _Inout_ PNGSCB_HSTI_RESULTS HstiResults,
    _Outptr_opt_result_maybenull_ PNGSCB_NAME_VALUE_COLLECTION *Information
    );

// rev
FVEAPI
HRESULT
WINAPI
NgscbCheckDmaSecurityEx(
    _Out_ PBOOLEAN IsDmaSecure,
    _Inout_ PNGSCB_HSTI_RESULTS HstiResults,
    _Outptr_opt_result_maybenull_ PNGSCB_NAME_VALUE_COLLECTION *Information,
    _Outptr_opt_result_maybenull_ PNGSCB_NAME_VALUE_COLLECTION *Capabilities
    );

// rev
FVEAPI
HRESULT
WINAPI
NgscbCheckHSTIPrerequisitesVerified(
    _Out_ PBOOLEAN PrerequisitesVerified,
    _In_ PNGSCB_HSTI_RESULTS HstiResults
    );

// rev
FVEAPI
HRESULT
WINAPI
NgscbCheckIsAOACDevice(
    _Out_ PBOOLEAN IsAoacDevice
    );

// rev
FVEAPI
HRESULT
WINAPI
NgscbCheckIsHSTIVerified(
    _Out_ PBOOLEAN IsHstiVerified,
    _Outptr_opt_result_maybenull_ PNGSCB_HSTI_RESULTS *HstiResults,
    _Out_opt_ PNGSCB_HSTI_PARSING_STATUS ParsingStatus
    );

// rev
FVEAPI
HRESULT
WINAPI
NgscbCheckPreventDeviceEncryption(
    _Out_ PBOOLEAN PreventDeviceEncryption
    );

// rev
FVEAPI
HRESULT
WINAPI
NgscbCheckPreventDeviceEncryptionForAad(
    _Out_ PBOOLEAN PreventDeviceEncryption
    );

// rev
FVEAPI
HRESULT
WINAPI
NgscbGetWinReConfiguration(
    _Out_ PBOOLEAN WinReAvailable,
    _Out_writes_opt_(ConfigurationCch) PWSTR Configuration,
    _In_ ULONG ConfigurationCch
    );

// rev
FVEAPI
HRESULT
WINAPI
NgscbIsHostOsOnRoamableDrive(
    _Out_ PBOOL IsRoamable
    );

// rev
FVEAPI
HRESULT
WINAPI
FveAddAuthMethodInformation(
    _In_ HANDLE FveVolumeHandle,
    _In_ PCFVE_AUTH_INFORMATION Information,
    _Out_ PGUID AuthMethodGuid
    );

// rev
FVEAPI
HRESULT
WINAPI
FveAddAuthMethodSid(
    _In_ HANDLE FveVolumeHandle,
    _In_ PCWSTR FriendlyName,
    _In_ PSID Sid,
    _In_ USHORT Flags,
    _Out_ PGUID AuthMethodGuid
    );

// rev
FVEAPI
HRESULT
WINAPI
FveAddPredictiveTpmProtector(
    _In_ PCWSTR FveVolumePath,
    _In_ PFVE_TPM_INFO FveTpmInfo
    );

// rev
FVEAPI
HRESULT
WINAPI
FveApplyGroupPolicy(
    _In_ HANDLE FveVolumeHandle
    );

// rev
FVEAPI
HRESULT
WINAPI
FveApplyNkpCertChanges(
    _In_ HANDLE FveVolumeHandle
    );

// rev
FVEAPI
HRESULT
WINAPI
FveAttemptAutoUnlock(
    _In_ HANDLE FveVolumeHandle
    );

// rev
FVEAPI
HRESULT
WINAPI
FveAuthElementFromPassPhraseW(
    _In_ PCWSTR PassPhrase,
    _Inout_ PFVE_AUTH_ELEMENT AuthElement
    );

// rev
FVEAPI
HRESULT
WINAPI
FveAuthElementFromPinW(
    _In_ PCWSTR Pin,
    _Inout_ PFVE_AUTH_ELEMENT AuthElement
    );

// rev
FVEAPI
HRESULT
WINAPI
FveAuthElementFromRecoveryPasswordW(
    _In_ PCWSTR RecoveryPassword,
    _Inout_ PFVE_AUTH_ELEMENT AuthElement
    );

// rev
FVEAPI
HRESULT
WINAPI
FveAuthElementGetKeyFileNameW(
    _In_ PCFVE_AUTH_INFORMATION Information,
    _Out_writes_(KeyFileNameCch) PWSTR KeyFileName,
    _In_ SIZE_T KeyFileNameCch
    );

// rev
FVEAPI
HRESULT
WINAPI
FveAuthElementReadExternalKeyW(
    _In_ PCWSTR KeyFullFilePath,
    _Inout_updates_bytes_(BufferSize) PFVE_AUTH_INFORMATION Information,
    _In_ SIZE_T BufferSize,
    _Out_ PSIZE_T RequiredSize
    );

// rev
FVEAPI
HRESULT
WINAPI
FveAuthElementToRecoveryPasswordW(
    _In_ PCFVE_AUTH_ELEMENT AuthElement,
    _Out_writes_(RecoveryPasswordCch) PWSTR RecoveryPassword,
    _In_ SIZE_T RecoveryPasswordCch
    );

// rev
FVEAPI
HRESULT
WINAPI
FveAuthElementWriteExternalKeyExW(
    _In_ PCGUID Identifier,
    _In_ PCWSTR KeyFullFilePath,
    _In_ PCFVE_AUTH_INFORMATION Information
    );

// rev
FVEAPI
HRESULT
WINAPI
FveAuthElementWriteExternalKeyW(
    _In_ PCWSTR KeyFullFilePath,
    _In_ PCFVE_AUTH_INFORMATION Information
    );

// rev
FVEAPI
HRESULT
WINAPI
FveBackupRecoveryInformationToAAD(
    _In_ HANDLE FveVolumeHandle,
    _In_ PCGUID AuthMethodGuid,
    _In_ ULONG Flags
    );

// rev
FVEAPI
HRESULT
WINAPI
FveBackupRecoveryInformationToAD(
    _In_ HANDLE FveVolumeHandle,
    _In_ PCGUID AuthMethodGuid
    );

// rev
FVEAPI
HRESULT
WINAPI
FveBackupRecoveryInformationToADEx(
    _In_ HANDLE FveVolumeHandle,
    _In_ PCGUID AuthMethodGuid,
    _In_ ULONG FveBackupFlags
    );

// rev
FVEAPI
HRESULT
WINAPI
FveBindDataVolume(
    _In_ HANDLE FveVolumeHandle,
    _In_ PCGUID AuthMethodGuid
    );

// rev
FVEAPI
HRESULT
WINAPI
FveCanPinExceptionPolicyBeApplied(
    _Out_ PBOOL Result
    );

// rev
FVEAPI
HRESULT
WINAPI
FveCanStandardUsersChangePassphraseByProxy(
    _In_ HANDLE FveVolumeHandle,
    _Out_ PBOOL CanChangePassphrase
    );

// rev
FVEAPI
HRESULT
WINAPI
FveCanStandardUsersChangePin(
    _Out_ PBOOL CanChangePin
    );

// rev
FVEAPI
HRESULT
WINAPI
FveCheckADRecoveryInfoBackupPolicy(
    _In_ HANDLE FveVolumeHandle,
    _Out_ PADA_GP_OPTIONS Options
    );

// rev
FVEAPI
HRESULT
WINAPI
FveCheckADRecoveryInfoBackupPolicyEx(
    _Out_opt_ PADA_GP_OPTIONS OsVolumeOptions,
    _Out_opt_ PADA_GP_OPTIONS FixedDataVolumeOptions,
    _Out_opt_ PADA_GP_OPTIONS RemovableDataVolumeOptions
    );

// rev
FVEAPI
HRESULT
WINAPI
FveCheckPassphrasePolicy(
    _In_ HANDLE FveVolumeHandle,
    _In_ PCWSTR Passphrase
    );

// rev
FVEAPI
HRESULT
WINAPI
FveCheckTpmCapability(
    _Inout_ PFVE_TPM_CAPS Capability
    );

// rev
FVEAPI
HRESULT
WINAPI
FveClearRecoveryPasswordBackupInformation(
    _In_ HANDLE FveVolumeHandle,
    _In_ PCGUID RecoveryPasswordGuid,
    _In_ USHORT BackupInformationType,
    _Out_ PBOOLEAN InformationChanged
    );

// rev
FVEAPI
HRESULT
WINAPI
FveClearUserFlags(
    _In_ HANDLE FveVolumeHandle,
    _In_ ULONG UserFlags
    );

// rev
FVEAPI
HRESULT
WINAPI
FveCloseHandle(
    _In_ HANDLE FveHandle
    );

// rev
FVEAPI
HRESULT
WINAPI
FveCloseVolume(
    _In_ HANDLE FveVolumeHandle
    );

// rev
FVEAPI
HRESULT
WINAPI
FveCommitChanges(
    _In_ HANDLE FveVolumeHandle
    );

// rev
FVEAPI
HRESULT
WINAPI
FveCommitChangesEx(
    _In_ HANDLE FveVolumeHandle,
    _In_ FVE_SCENARIO_TYPE FveScenario
    );

// rev
FVEAPI
HRESULT
WINAPI
FveControl(
    _In_ FVE_CONTROL_TYPE ControlType,
    _In_reads_bytes_opt_(InputSize) PBYTE InputBuffer,
    _In_ ULONG InputSize,
    _Out_writes_bytes_opt_(*OutputSize) PBYTE OutputBuffer,
    _Inout_ PULONG OutputSize
    );

// rev
FVEAPI
HRESULT
WINAPI
FveConversionDecrypt(
    _In_ HANDLE FveVolumeHandle
    );

// rev
FVEAPI
HRESULT
WINAPI
FveConversionDecryptEx(
    _In_ HANDLE FveVolumeHandle,
    _In_ ULONG ConversionFlags
    );

// rev
FVEAPI
HRESULT
WINAPI
FveConversionEncrypt(
    _In_ HANDLE FveVolumeHandle
    );

// rev
FVEAPI
HRESULT
WINAPI
FveConversionEncryptEx(
    _In_ HANDLE FveVolumeHandle,
    _In_ ULONG ConversionFlags
    );

// rev
FVEAPI
HRESULT
WINAPI
FveConversionEncryptPendingReboot(
    _In_ HANDLE FveVolumeHandle
    );

// rev
FVEAPI
HRESULT
WINAPI
FveConversionEncryptPendingRebootEx(
    _In_ HANDLE FveVolumeHandle,
    _In_ ULONG ConversionFlags
    );

// rev
FVEAPI
HRESULT
WINAPI
FveConversionPause(
    _In_ HANDLE FveVolumeHandle
    );

// rev
FVEAPI
HRESULT
WINAPI
FveConversionResume(
    _In_ HANDLE FveVolumeHandle
    );

// rev
FVEAPI
HRESULT
WINAPI
FveConversionStop(
    _In_ HANDLE FveVolumeHandle
    );

// rev
FVEAPI
HRESULT
WINAPI
FveConversionStopEx(
    _In_ HANDLE FveVolumeHandle,
    _In_ BOOLEAN AutoStartOnReinsertion
    );

// rev
FVEAPI
HRESULT
WINAPI
FveDecrementClearKeyCounter(
    _In_ HANDLE FveVolumeHandle
    );

// rev
FVEAPI
HRESULT
WINAPI
FveDeleteAuthMethod(
    _In_ HANDLE FveVolumeHandle,
    _In_ PCGUID AuthMethodGuid
    );

// rev
FVEAPI
HRESULT
WINAPI
FveDeleteDeviceEncryptionOptOutForVolumeW(
    _In_ PCWSTR VolumePath
    );

// rev
FVEAPI
HRESULT
WINAPI
FveDisableDeviceLockoutState(
    _In_ HANDLE FveVolumeHandle
    );

// rev
FVEAPI
HRESULT
WINAPI
FveDiscardChanges(
    _In_ HANDLE FveVolumeHandle
    );

// rev
FVEAPI
HRESULT
WINAPI
FveDraCertPresentInRegistry(
    _Out_ PBOOL CertPresent
    );

// rev
FVEAPI
HRESULT
WINAPI
FveEnableRawAccess(
    _In_ HANDLE FveVolumeHandle,
    _In_ BOOL Enabled
    );

// rev
FVEAPI
HRESULT
WINAPI
FveEnableRawAccessEx(
    _In_ HANDLE FveVolumeHandle,
    _In_ BOOL Enabled,
    _In_ BOOL ForceDismount
    );

// rev
FVEAPI
HRESULT
WINAPI
FveEnableRawAccessW(
    _In_ PCWSTR VolumeName,
    _In_ BOOL Enabled
    );

// rev
FVEAPI
HRESULT
WINAPI
FveEraseDrive(
    _In_ HANDLE FveVolumeHandle,
    _In_ BOOL ForceDismount
    );

// rev
FVEAPI
HRESULT
WINAPI
FveEscrowEncryptedRecoveryKeyForRetailUnlock(
    _In_reads_bytes_(BufferSize) PBYTE Buffer,
    _In_ DWORD BufferSize
    );

// rev
FVEAPI
HRESULT
WINAPI
FveExternalDataCreateEntry(
    _In_ HANDLE FveVolumeHandle,
    _In_ ULONG Flags,
    _Inout_ PFVE_EXTERNAL_DATA_ENTRY_INFO_V1 EntryInfo,
    _In_ USHORT DataSize,
    _In_reads_bytes_(DataSize) PBYTE Data
    );

// rev
FVEAPI
HRESULT
WINAPI
FveExternalDataDeleteEntries(
    _In_ HANDLE FveVolumeHandle,
    _In_ PCFVE_EXTERNAL_DATA_ENTRY_SELECT_V1 Selection,
    _Out_opt_ PUSHORT DeletedEntryCount
    );

// rev
FVEAPI
HRESULT
WINAPI
FveExternalDataGetEntryInfo(
    _In_ HANDLE FveVolumeHandle,
    _In_ PCFVE_EXTERNAL_DATA_ENTRY_SELECT_V1 Selection,
    _In_ USHORT EntryInfoVersion,
    _In_ ULONG EntryInfoBufferSize,
    _Out_ PULONG RequiredSize,
    _Out_ PUSHORT EntryCount,
    _Out_writes_bytes_opt_(EntryInfoBufferSize) PFVE_EXTERNAL_DATA_ENTRY_INFO_V1 EntryInfo
    );

// rev
FVEAPI
HRESULT
WINAPI
FveExternalDataGetEntryRawData(
    _In_ HANDLE FveVolumeHandle,
    _In_ PCFVE_EXTERNAL_DATA_ENTRY_SELECT_V1 Selection,
    _In_ USHORT DataBufferSize,
    _Out_ PUSHORT DataSize,
    _Out_writes_bytes_opt_(DataBufferSize) PBYTE Data
    );

// rev
FVEAPI
HRESULT
WINAPI
FveFindFirstVolume(
    _Out_ PHANDLE FveFindHandle,
    _Inout_opt_ PFVE_FIND_DATA_V1 FindData
    );

// rev
FVEAPI
HRESULT
WINAPI
FveFindNextVolume(
    _In_ HANDLE FveFindHandle,
    _Inout_opt_ PFVE_FIND_DATA_V1 FindData
    );

// rev
FVEAPI
HRESULT
WINAPI
FveFlagsToProtectorType(
    _In_ ULONG TypeFlags,
    _Out_ PFVE_PROTECTOR_TYPE ProtectorType
    );

// rev
FVEAPI
HRESULT
WINAPI
FveGenerateNbp(
    _In_ HANDLE FveVolumeHandle,
    _In_ DWORD CertThumbprintSize,
    _In_reads_bytes_(CertThumbprintSize) PBYTE CertThumbprint
    );

// rev
FVEAPI
HRESULT
WINAPI
FveGenerateNkpSessionKeys(
    _In_ HANDLE FveVolumeHandle
    );

// rev
FVEAPI
HRESULT
WINAPI
FveGetAllowKeyExport(
    _Out_ PBOOL Allow
    );

// rev
FVEAPI
HRESULT
WINAPI
FveGetAuthMethodGuids(
    _In_ HANDLE FveVolumeHandle,
    _Out_writes_to_opt_(MaxAuthMethodGuids, *AuthMethodGuidCount) PGUID AuthMethodGuids,
    _In_ UINT MaxAuthMethodGuids,
    _Out_ PUINT AuthMethodGuidCount
    );

// rev
FVEAPI
HRESULT
WINAPI
FveGetAuthMethodInformation(
    _In_ HANDLE FveVolumeHandle,
    _Inout_updates_bytes_(BufferSize) PFVE_AUTH_INFORMATION Information,
    _In_ SIZE_T BufferSize,
    _Out_ PSIZE_T RequiredSize
    );

// rev
FVEAPI
HRESULT
WINAPI
FveGetAuthMethodSid(
    _In_ HANDLE FveVolumeHandle,
    _In_ PSID Sid,
    _Out_writes_to_opt_(*AuthMethodCount, *AuthMethodCount) PGUID AuthMethodGuids,
    _Inout_ PULONG AuthMethodCount
    );

// rev
FVEAPI
HRESULT
WINAPI
FveGetAuthMethodSidInformation(
    _In_ HANDLE FveVolumeHandle,
    _In_ PCGUID AuthMethodGuid,
    _Out_ PUSHORT Flags,
    _Out_writes_bytes_opt_(*SidBufferSize) PSID Sid,
    _Inout_ PULONG SidBufferSize
    );

// rev
FVEAPI
HRESULT
WINAPI
FveGetClearKeyCounter(
    _In_ HANDLE FveVolumeHandle,
    _Out_ PULONG ClearKeyCounter
    );

// rev
FVEAPI
HRESULT
WINAPI
FveGetDataSet(
    _In_ HANDLE FveVolumeHandle,
    _Out_writes_bytes_(DataSetBufferSize) PBYTE DataSetBuffer,
    _In_ SIZE_T DataSetBufferSize,
    _Out_ PSIZE_T ActualDataSetBufferSize
    );

// rev
FVEAPI
HRESULT
WINAPI
FveGetDataSetEx(
    _In_ HANDLE FveVolumeHandle,
    _In_ BOOL IgnoreLockVolumeCheck,
    _Out_writes_bytes_(DataSetBufferSize) PBYTE DataSetBuffer,
    _In_ SIZE_T DataSetBufferSize,
    _Out_ PSIZE_T ActualDataSetBufferSize
    );

// rev
FVEAPI
HRESULT
WINAPI
FveGetDescriptionW(
    _In_ HANDLE FveVolumeHandle,
    _Out_writes_opt_(BufferLength) PWSTR VolumeDescription,
    _In_ SIZE_T BufferLength,
    _Out_ PSIZE_T RequiredSize
    );

// rev
FVEAPI
HRESULT
WINAPI
FveGetDeviceLockoutData(
    _In_ HANDLE FveVolumeHandle,
    _Out_writes_bytes_opt_(*PerUserSize) PBYTE PerUserData,
    _Inout_ PULONG PerUserSize
    );

// Zero the returned sensitive buffer before freeing it with HeapFree(GetProcessHeap(), ...).
// rev
FVEAPI
HRESULT
WINAPI
FveGetExternalKeyBlob(
    _Outptr_result_bytebuffer_(*BufferSize) PBYTE *Buffer,
    _Out_ PDWORD BufferSize
    );

// rev
FVEAPI
HRESULT
WINAPI
FveGetFipsAllowDisabled(
    _Out_ PBOOL Allow
    );

// rev
FVEAPI
HRESULT
WINAPI
FveGetFveMethod(
    _In_ HANDLE FveVolumeHandle,
    _Out_ PFVE_LEGACY_METHOD FveMethod
    );

// rev
FVEAPI
HRESULT
WINAPI
FveGetFveMethodEDrv(
    _In_ HANDLE FveVolumeHandle,
    _Out_ PFVE_LEGACY_METHOD FveMethod,
    _Out_writes_(FVE_EDRIVE_METHOD_CCH) PWSTR SelfEncryptionDriveMethod
    );

// rev
FVEAPI
HRESULT
WINAPI
FveGetFveMethodEx(
    _In_ HANDLE FveVolumeHandle,
    _Out_ PFVE_LEGACY_METHOD FveMethod,
    _Out_writes_(FVE_EDRIVE_METHOD_CCH) PWSTR SelfEncryptionDriveMethod,
    _Out_ PULONG FveMethodFlags
    );

// rev
FVEAPI
HRESULT
WINAPI
FveGetIdentificationFieldW(
    _In_ HANDLE FveVolumeHandle,
    _Out_writes_opt_(BufferLength) PWSTR IdentificationField,
    _In_ SIZE_T BufferLength,
    _Out_ PSIZE_T RequiredSize
    );

// rev
FVEAPI
HRESULT
WINAPI
FveGetIdentity(
    _In_ HANDLE FveVolumeHandle,
    _Out_ PGUID IdentityGuid
    );

// rev
FVEAPI
HRESULT
WINAPI
FveGetKeyPackage(
    _In_ HANDLE FveVolumeHandle,
    _In_ PCGUID Identifier,
    _Out_writes_bytes_opt_(BufferSize) PBYTE Buffer,
    _In_ SIZE_T BufferSize,
    _Out_ PSIZE_T DataSize
    );

// rev
FVEAPI
HRESULT
WINAPI
FveGetRecoveryPasswordBackupAccountInformation(
    _In_ HANDLE FveVolumeHandle,
    _In_ PCGUID RecoveryPasswordGuid,
    _In_ USHORT BackupInformationType,
    _In_ SIZE_T AccountNameCch,
    _Out_ PSIZE_T RequiredCch,
    _Out_writes_opt_(AccountNameCch) PWSTR AccountName
    );

// rev
FVEAPI
HRESULT
WINAPI
FveGetRecoveryPasswordBackupInformation(
    _In_ HANDLE FveVolumeHandle,
    _In_opt_ PCGUID RecoveryPasswordGuid,
    _Out_ PUSHORT BackupInformation
    );

// rev
FVEAPI
HRESULT
WINAPI
FveGetSecureBootBindingState(
    _Out_ PFVE_SECUREBOOT_BINDING_STATE BindingState
    );

// rev
FVEAPI
HRESULT
WINAPI
FveGetStatus(
    _In_ HANDLE FveVolumeHandle,
    _Inout_ PFVE_STATUS_V9 Status
    );

// rev
FVEAPI
HRESULT
WINAPI
FveGetStatusW(
    _In_ PCWSTR VolumeName,
    _Inout_ PFVE_STATUS_V9 Status
    );

// rev
FVEAPI
HRESULT
WINAPI
FveGetUserFlags(
    _In_ HANDLE FveVolumeHandle,
    _Out_ PULONG UserFlags
    );

// rev
FVEAPI
HRESULT
WINAPI
FveGetVolumeNameW(
    _In_ HANDLE FveHandle,
    _Inout_ PULONG VolumeNameBufferCchLen,
    _Out_writes_opt_(*VolumeNameBufferCchLen) PWSTR VolumeName
    );

// rev
FVEAPI
HRESULT
WINAPI
FveInitVolume(
    _In_ HANDLE FveVolumeHandle,
    _In_opt_ PCWSTR DiscoveryVolumeType
    );

// rev
FVEAPI
HRESULT
WINAPI
FveInitVolumeEx(
    _In_ HANDLE FveVolumeHandle,
    _In_opt_ PCWSTR DiscoveryVolumeType,
    _In_ ULONG InitializationFlags
    );

// rev
FVEAPI
HRESULT
WINAPI
FveInitializeDeviceEncryption(
    VOID
    );

// rev
FVEAPI
HRESULT
WINAPI
FveInitializeDeviceEncryption2(
    _In_ HANDLE FveVolumeHandle,
    _In_ ULONG InitializationFlags
    );

// rev
FVEAPI
HRESULT
WINAPI
FveIsAnyDataVolumeBoundToOSVolume(
    _In_ HANDLE FveVolumeHandle,
    _Out_ PULONG BoundVolumeCount
    );

// rev
FVEAPI
HRESULT
WINAPI
FveIsBoundDataVolume(
    _In_ HANDLE FveVolumeHandle,
    _Out_ PBOOL IsAutoUnlockEnabled,
    _Out_ PGUID UnlockGuid
    );

// rev
FVEAPI
HRESULT
WINAPI
FveIsBoundDataVolumeToOSVolume(
    _In_ HANDLE FveVolumeHandle,
    _Out_ PBOOL IsAutoUnlockEnabled,
    _Out_ PGUID UnlockGuid
    );

// rev
FVEAPI
HRESULT
WINAPI
FveIsDeviceLockable(
    _In_ HANDLE FveVolumeHandle
    );

// rev
FVEAPI
HRESULT
WINAPI
FveIsDeviceLockedOut(
    _In_ HANDLE FveVolumeHandle,
    _Out_ PBOOL IsDeviceLocked
    );

// rev
FVEAPI
HRESULT
WINAPI
FveIsHardwareReadyForConversion(
    VOID
    );

// rev
FVEAPI
HRESULT
WINAPI
FveIsHybridVolume(
    _In_ HANDLE FveVolumeHandle,
    _Out_ PBOOL IsHybrid
    );

// rev
FVEAPI
HRESULT
WINAPI
FveIsHybridVolumeW(
    _In_ PCWSTR VolumeName,
    _Out_ PBOOL IsHybrid
    );

// rev
FVEAPI
HRESULT
WINAPI
FveIsPassphraseCompatibleW(
    _In_ PCWSTR Passphrase,
    _Out_ PBOOL IsCompatible
    );

// rev
FVEAPI
HRESULT
WINAPI
FveIsRecoveryPasswordGroupValidW(
    _In_ PCWSTR RecoveryPasswordGroup,
    _Out_ PBOOLEAN IsValid
    );

// rev
FVEAPI
HRESULT
WINAPI
FveIsRecoveryPasswordValidW(
    _In_ PCWSTR RecoveryPassword,
    _Out_ PBOOLEAN IsValid
    );

// rev
FVEAPI
HRESULT
WINAPI
FveIsSchemaExtInstalled(
    _Out_ PBOOL SchemaExtInstalled
    );

// rev
FVEAPI
HRESULT
WINAPI
FveIsVolumeEncryptable(
    _In_ HANDLE FveVolumeHandle
    );

// rev
FVEAPI
HRESULT
WINAPI
FveKeyManagement(
    _In_ HANDLE FveVolumeHandle,
    _In_ ULONG FlagsIn,
    _Out_opt_ PULONG FlagsOut
    );

// rev
FVEAPI
HRESULT
WINAPI
FveLockDevice(
    _In_ HANDLE FveVolumeHandle
    );

// rev
FVEAPI
HRESULT
WINAPI
FveLockVolume(
    _In_ HANDLE FveVolumeHandle,
    _In_ BOOLEAN ForceDismount
    );

// rev
FVEAPI
HRESULT
WINAPI
FveLogRecoveryReason(
    _In_ HANDLE FveVolumeHandle,
    _In_ DWORD RecoveryReason,
    _In_opt_ PCWSTR ApplicationPath,
    _In_ DWORD ChangedBcd
    );

// rev
FVEAPI
HRESULT
WINAPI
FveNeedsDiscoveryVolumeUpdate(
    _In_ HANDLE FveVolumeHandle,
    _Out_ PBOOL NeedsUpdate
    );

// rev
FVEAPI
HRESULT
WINAPI
FveNotifyVolumeAfterFormat(
    _In_ HANDLE FveVolumeHandle
    );

// rev
FVEAPI
HRESULT
WINAPI
FveOpenVolumeByHandle(
    _In_ HANDLE Handle,
    _In_ FVE_HANDLE_TYPE HandleType,
    _In_ BOOL NeedWriteAccess,
    _In_ FVE_INTERFACE_TYPE InterfaceType,
    _In_ ULONG HandleFlags,
    _Out_ PHANDLE FveVolumeHandle
    );

// rev
FVEAPI
HRESULT
WINAPI
FveOpenVolumeExW(
    _In_ PCWSTR VolumeName,
    _In_ ULONG NameFlags,
    _In_ BOOL NeedWriteAccess,
    _In_ FVE_INTERFACE_TYPE InterfaceType,
    _In_ ULONG HandleFlags,
    _Out_ PHANDLE FveVolumeHandle
    );

// rev
FVEAPI
HRESULT
WINAPI
FveOpenVolumeW(
    _In_ PCWSTR VolumeName,
    _In_ BOOL NeedWriteAccess,
    _Out_ PHANDLE FveVolumeHandle
    );

// rev
FVEAPI
HRESULT
WINAPI
FvePpfPredictionsUpdated(
    _In_ PPPF_PREDICTIONS_UPDATED_CONTEXT Context
    );

// rev
FVEAPI
HRESULT
WINAPI
FveProtectorTypeToFlags(
    _In_ FVE_PROTECTOR_TYPE ProtectorType,
    _Out_ PULONG TypeFlags
    );

// rev
FVEAPI
HRESULT
WINAPI
FveQuery(
    _In_ FVE_QUERY_TYPE QueryType,
    _In_reads_bytes_opt_(InputSize) PBYTE InputBuffer,
    _In_ ULONG InputSize,
    _Out_writes_bytes_opt_(*OutputSize) PBYTE OutputBuffer,
    _Inout_ PULONG OutputSize
    );

// rev
FVEAPI
HRESULT
WINAPI
FveQueryDeviceEncryptionSupport(
    _Inout_ PFVE_DE_SUPPORT DeviceEncryptionSupport
    );

// rev
FVEAPI
HRESULT
WINAPI
FveRecalculateOffsetsAndMoveMetadata(
    _In_ HANDLE FveVolumeHandle
    );

// rev
FVEAPI
HRESULT
WINAPI
FveRegenerateNbpSessionKey(
    _In_ HANDLE FveVolumeHandle
    );

// rev
FVEAPI
HRESULT
WINAPI
FveResetTpmDictionaryAttackParameters(
    VOID
    );

// rev
FVEAPI
HRESULT
WINAPI
FveRevertVolume(
    _In_ HANDLE FveVolumeHandle
    );

// rev
FVEAPI
HRESULT
WINAPI
FveSaveRecoveryPasswordBackupFlag(
    _In_ HANDLE FveVolumeHandle,
    _In_ PCGUID RecoveryPasswordGuid,
    _In_ PCFVE_AUTH_ELEMENT RecoveryPassword
    );

// rev
FVEAPI
HRESULT
WINAPI
FveSelectBestRecoveryPasswordByBackupInformation(
    _In_ HANDLE FveVolumeHandle,
    _Out_ PGUID RecoveryPasswordGuid
    );

// rev
FVEAPI
HRESULT
WINAPI
FveServiceDiscoveryVolume(
    _In_ HANDLE FveVolumeHandle
    );

// rev
FVEAPI
HRESULT
WINAPI
FveSetAllowKeyExport(
    _In_ BOOL Allow
    );

// rev
FVEAPI
HRESULT
WINAPI
FveSetDescriptionW(
    _In_ HANDLE FveVolumeHandle,
    _In_ PCWSTR VolumeDescription
    );

// rev
FVEAPI
HRESULT
WINAPI
FveSetFipsAllowDisabled(
    _In_ BOOL Allow
    );

// rev
FVEAPI
HRESULT
WINAPI
FveSetFveMethod(
    _In_ HANDLE FveVolumeHandle,
    _In_ FVE_LEGACY_METHOD FveMethod
    );

// rev
FVEAPI
HRESULT
WINAPI
FveSetFveMethodEx(
    _In_ HANDLE FveVolumeHandle,
    _In_ FVE_METHOD FveMethod,
    _In_ FVE_METHOD_STRENGTH Strength,
    _In_ ULONG Flags
    );

// rev
FVEAPI
HRESULT
WINAPI
FveSetIdentificationFieldW(
    _In_ HANDLE FveVolumeHandle,
    _In_ PCWSTR IdentificationField
    );

// rev
FVEAPI
HRESULT
WINAPI
FveSetRecoveryPasswordBackupAccountInformation(
    _In_ HANDLE FveVolumeHandle,
    _In_ PCGUID RecoveryPasswordGuid,
    _In_ USHORT BackupInformationType,
    _In_ PCWSTR AccountName,
    _Out_ PBOOLEAN InformationChanged
    );

// rev
FVEAPI
HRESULT
WINAPI
FveSetRecoveryPasswordBackupInformation(
    _In_ HANDLE FveVolumeHandle,
    _In_ PCGUID RecoveryPasswordGuid,
    _In_ USHORT BackupInformationType,
    _In_ USHORT FlagsToSet,
    _In_ USHORT FlagsToClear,
    _Out_ PBOOLEAN InformationChanged
    );

// rev
FVEAPI
HRESULT
WINAPI
FveSetUserFlags(
    _In_ HANDLE FveVolumeHandle,
    _In_ ULONG UserFlags
    );

// rev
FVEAPI
HRESULT
WINAPI
FveSetupTpmCallback(
    _In_ PFVE_TPM_API_CALLBACK TpmCallback,
    _In_ UINT32 TpmVersion
    );

// rev
FVEAPI
HRESULT
WINAPI
FveSysClearUserFlags(
    _In_ HANDLE FveSysHandle,
    _In_ ULONG UserFlags
    );

// rev
FVEAPI
HRESULT
WINAPI
FveSysCloseVolume(
    _In_ HANDLE FveSysHandle
    );

// rev
FVEAPI
HRESULT
WINAPI
FveSysGetUserFlags(
    _In_ HANDLE FveSysHandle,
    _Out_ PULONG UserFlags
    );

// rev
FVEAPI
HRESULT
WINAPI
FveSysOpenVolumeW(
    _In_ PCWSTR VolumeName,
    _Out_ PHANDLE FveSysHandle
    );

// rev
FVEAPI
HRESULT
WINAPI
FveSysSetUserFlags(
    _In_ HANDLE FveSysHandle,
    _In_ ULONG UserFlags
    );

// rev
FVEAPI
HRESULT
WINAPI
FveUnbindAllDataVolumeFromOSVolume(
    _In_ HANDLE FveVolumeHandle
    );

// rev
FVEAPI
HRESULT
WINAPI
FveUnbindDataVolume(
    _In_ HANDLE FveVolumeHandle
    );

// rev
FVEAPI
HRESULT
WINAPI
FveUnlockVolume(
    _In_ HANDLE FveVolumeHandle,
    _In_ PCFVE_AUTH_INFORMATION Information
    );

// rev
FVEAPI
HRESULT
WINAPI
FveUnlockVolumeAuthMethodSid(
    _In_ HANDLE FveVolumeHandle,
    _In_ PCGUID AuthMethodGuid
    );

// rev
FVEAPI
HRESULT
WINAPI
FveUnlockVolumeWithAccessMode(
    _In_ HANDLE FveVolumeHandle,
    _In_ PCFVE_AUTH_INFORMATION Information,
    _Out_ PBOOL ReadOnly
    );

// rev
FVEAPI
HRESULT
WINAPI
FveUpdateBandIdBcd(
    _In_ HANDLE FveVolumeHandle
    );

// rev
FVEAPI
HRESULT
WINAPI
FveUpdateDeviceLockoutState(
    _In_ HANDLE FveVolumeHandle,
    _In_reads_bytes_(PerUserSize) PBYTE PerUserData,
    _In_ ULONG PerUserSize
    );

// rev
FVEAPI
HRESULT
WINAPI
FveUpdateDeviceLockoutStateEx(
    _In_ HANDLE FveVolumeHandle,
    _In_reads_bytes_(PerUserSize) PBYTE PerUserData,
    _In_ ULONG PerUserSize,
    _In_ ULONG Flags
    );

// rev
FVEAPI
HRESULT
WINAPI
FveUpdatePinW(
    _In_ HANDLE FveVolumeHandle,
    _In_ PCWSTR NewPin,
    _In_ PCGUID ProtectorGuid
    );

// rev
FVEAPI
HRESULT
WINAPI
FveUpgradeVolume(
    _In_ HANDLE FveVolumeHandle
    );

// rev
FVEAPI
HRESULT
WINAPI
FveValidateDeviceLockoutState(
    _In_ HANDLE FveVolumeHandle
    );

// rev
FVEAPI
HRESULT
WINAPI
FveValidateExistingPassphraseW(
    _In_ HANDLE FveVolumeHandle,
    _In_ PCWSTR ExistingPassphrase,
    _Out_ PBOOL ExistingPassphraseValidates,
    _Out_ PGUID ProtectorGuid
    );

// rev
FVEAPI
HRESULT
WINAPI
FveValidateExistingPinW(
    _In_ HANDLE FveVolumeHandle,
    _In_ PCWSTR ExistingPin,
    _Out_ PBOOL ExistingPinValidates,
    _Out_ PGUID ProtectorGuid
    );

EXTERN_C_END
