#include <efi.h>
#include <efilib.h>

#define ERR_PRT(a)  do { Print(L"%a(line %d):", __FILE__, __LINE__); Print a; Print(L"\n"); } while (0);
#define PTR_FMT L"0x%lx"

#define EFI_TCG_PROTOCOL_GUID \
{ 0xf541796d, 0xa62e, 0x4954, {0xa7, 0x75, 0x95, 0x84, 0xf6, 0x1b, 0x9c, 0xdd} }

EFI_GUID TcgProtocol  = EFI_TCG_PROTOCOL_GUID;

typedef struct _TCG_VERSION {
    UINT8 Major;
    UINT8 Minor;
    UINT8 RevMajor;
    UINT8 RevMinor;
} TCG_VERSION;

typedef struct _TCG_BOOT_SERVICE_CAPABILITY {
    UINT8       Size;
    struct _TCG_VERSION StructureVersion;
    struct _TCG_VERSION ProtocolSpecVersion;
    UINT8       HashAlgorithmBitmap;
    BOOLEAN     TPMPresentFlag;
    BOOLEAN     TPMDeactivatedFlag;
} TCG_BOOT_SERVICE_CAPABILITY;

typedef UINT32 TCG_ALGORITHM_ID;
#define TCG_ALG_SHA 0x00000004 // The SHA1 algorithm

#define SHA1_DIGEST_SIZE 20

typedef struct _TCG_DIGEST {
    UINT8 Digest[SHA1_DIGEST_SIZE];
} TCG_DIGEST;

typedef TCG_DIGEST TCG_COMPOSITE_HASH;

typedef UINT32 TCG_PCRINDEX;
typedef UINT32 TCG_EVENTTYPE;

//
// Log event types (Standard ..)
//
#define EV_NO_ACTION 3
#define EV_SEPARATOR 4
#define EV_ACTION 5
#define EV_EVENT_TAG 6
#define EV_CPU_MICROCODE 9
#define EV_PLATFORM_CONFIG_FLAGS 10
#define EV_IPL 13
#define EV_IPL_PARTITION_DATA 14
#define EV_NONHOST_CODE 15
#define EV_NONHOST_CONFIG 16

//
// EFI specific event types
// TCG EFI Platform Spec, Chap 7.2
//
#define EV_EFI_EVENT_BASE                   ((TCG_EVENTTYPE) 0x80000000)
#define EV_EFI_VARIABLE_DRIVER_CONFIG       (EV_EFI_EVENT_BASE + 1)
#define EV_EFI_VARIABLE_BOOT                (EV_EFI_EVENT_BASE + 2)
#define EV_EFI_BOOT_SERVICES_APPLICATION    (EV_EFI_EVENT_BASE + 3)
#define EV_EFI_BOOT_SERVICES_DRIVER         (EV_EFI_EVENT_BASE + 4)
#define EV_EFI_RUNTIME_SERVICES_DRIVER      (EV_EFI_EVENT_BASE + 5)
#define EV_EFI_GPT_EVENT                    (EV_EFI_EVENT_BASE + 6)
#define EV_EFI_ACTION                       (EV_EFI_EVENT_BASE + 7)
#define EV_EFI_PLATFORM_FIRMWARE_BLOB       (EV_EFI_EVENT_BASE + 8)
#define EV_EFI_HANDOFF_TABLES               (EV_EFI_EVENT_BASE + 9)


typedef struct _TCG_PCR_EVENT {
    TCG_PCRINDEX PCRIndex; 
    TCG_EVENTTYPE EventType; 
    struct _TCG_DIGEST digest;
    UINT32 EventSize;
    UINT8 Event[1];
} TCG_PCR_EVENT;


INTERFACE_DECL(_EFI_TCG);

typedef
EFI_STATUS
(EFIAPI *EFI_TCG_STATUS_CHECK) (
    IN  struct _EFI_TCG *This,
    OUT struct _TCG_BOOT_SERVICE_CAPABILITY *ProtocolCapability,
    OUT UINT32 *TCGFeatureFlags,
    OUT EFI_PHYSICAL_ADDRESS *EventLogLocation,
    OUT EFI_PHYSICAL_ADDRESS *EventLogLastEntry
    );

typedef
EFI_STATUS
(EFIAPI *EFI_TCG_HASH_ALL) (
    IN struct _EFI_TCG *This,
    IN UINT8 *HashData,
    IN UINT64 HashDataLen,
    IN TCG_ALGORITHM_ID AlgorithmId,
    IN OUT UINT64 *HashedDataLen,
    IN OUT UINT8 **HashedDataResult
    );

typedef
EFI_STATUS
(EFIAPI *EFI_TCG_LOG_EVENT) (
    IN struct _EFI_TCG *This,
    IN struct _TCG_PCR_EVENT *TCGLogData,
    IN OUT UINT32 *EventNumber,
    IN UINT32 Flags
);


typedef
EFI_STATUS
(EFIAPI *EFI_TCG_PASS_THROUGH_TO_TPM) (
    IN struct _EFI_TCG *This,
    IN UINT32 TpmInputParameterBlockSize,
    IN UINT8 *TpmInputParameterBlock,
    IN UINT32 TpmOutputParameterBlockSize,
    IN UINT8 *TpmOutputParameterBlock
);

typedef
EFI_STATUS
(EFIAPI *EFI_TCG_HASH_LOG_EXTEND_EVENT) (
    IN struct _EFI_TCG *This,
    IN EFI_PHYSICAL_ADDRESS HashData,
    IN UINT64 HashDataLen,
    IN TCG_ALGORITHM_ID AlgorithmId,
    IN struct _TCG_PCR_EVENT *TCGLogData,
    IN OUT UINT32 *EventNumber,
    OUT EFI_PHYSICAL_ADDRESS *EventLogLastEntry
);

typedef struct _EFI_TCG {
    EFI_TCG_STATUS_CHECK          StatusCheck;
    EFI_TCG_HASH_ALL              HashAll;
    EFI_TCG_LOG_EVENT             LogEvent;
    EFI_TCG_PASS_THROUGH_TO_TPM   PassThroughToTPM;
    EFI_TCG_HASH_LOG_EXTEND_EVENT HashLogExtendEvent;
} EFI_TCG;


static EFI_STATUS
measure_file_to_pcr8_and_event_log (EFI_FILE_HANDLE fs, EFI_TCG *tcg, CHAR16 *path, BOOLEAN to_event_log)
{
    EFI_STATUS status;
    EFI_FILE_HANDLE fh;
    EFI_FILE_INFO *f_info;
    TCG_PCR_EVENT *tcg_event;
    VOID *buffer;
    UINTN buffer_size;

    UINT32 event_number;
    EFI_PHYSICAL_ADDRESS event_log_last;

    status = uefi_call_wrapper (fs->Open, 5, fs, &fh, path, EFI_FILE_MODE_READ, 0);
    if (EFI_ERROR(status)) {
        ERR_PRT((L"open config failed"));
        return EFI_LOAD_ERROR;
    }

    f_info = LibFileInfo (fh);
    if (!f_info) {
        ERR_PRT((L"get file info failed"));
        return EFI_LOAD_ERROR;
    }

    Print(L"File Size      : %ld bytes\n", f_info->FileSize);

    buffer_size = f_info->FileSize + EFI_PAGE_SIZE;
    buffer = AllocatePool (buffer_size);
    
    if (!buffer) {
        ERR_PRT((L"out of resource"));
        return EFI_OUT_OF_RESOURCES;
    }

    status = uefi_call_wrapper(fh->Read, 3, fh, &buffer_size, buffer);
    if (EFI_ERROR(status)) {
        ERR_PRT((L"read config failed"));
        return EFI_LOAD_ERROR;
    }

    Print(L"file:	%d bytes successfully read\n", buffer_size);

    if (to_event_log) {
        tcg_event = AllocateZeroPool (buffer_size + sizeof (TCG_PCR_EVENT) - 1);
        tcg_event->EventSize = buffer_size;
        CopyMem ((VOID*)&tcg_event->Event, (VOID*)buffer, buffer_size);
    } else {
        tcg_event = AllocateZeroPool (sizeof (TCG_PCR_EVENT));
    }

    tcg_event->PCRIndex = 8;
    tcg_event->EventType = EV_EFI_PLATFORM_FIRMWARE_BLOB;

    event_number = 1;
    status = uefi_call_wrapper(tcg->HashLogExtendEvent, 7, 
                               tcg, buffer, buffer_size, TCG_ALG_SHA,
                               tcg_event, &event_number, &event_log_last);

    if (EFI_ERROR(status)) {
        ERR_PRT((L"TCG HashLogExtendEvent Failed\n"));
        return EFI_LOAD_ERROR;
    }

    status = uefi_call_wrapper(fh->Close, 1, fh);
    if (EFI_ERROR(status)) {
        ERR_PRT((L"close file handle failed"));
        return EFI_LOAD_ERROR;
    }

    uefi_call_wrapper(BS->FreePool, 1, f_info);
    uefi_call_wrapper(BS->FreePool, 1, buffer);
    uefi_call_wrapper(BS->FreePool, 1, tcg_event);

    return EFI_SUCCESS;
}

static EFI_TCG *
tcg_interface_check ()
{
    EFI_STATUS status;
    EFI_TCG *tcg;
    TCG_BOOT_SERVICE_CAPABILITY capability;
    UINT32 features;
    EFI_PHYSICAL_ADDRESS event_log_location;
    EFI_PHYSICAL_ADDRESS event_log_last_entry;

    status = LibLocateProtocol (&TcgProtocol,  (void **)&tcg);

    if (EFI_ERROR(status)) {
        ERR_PRT((L"no EFI_TCG protocol installed\n"));
        return NULL;
    }

    status = uefi_call_wrapper(tcg->StatusCheck, 5, tcg, &capability, &features, &event_log_location, &event_log_last_entry);

    if (EFI_ERROR(status)) {
        ERR_PRT((L"no EFI_TCG StatusCheck failed\n"));
        return NULL;
    }

    if (capability.TPMDeactivatedFlag) {
        ERR_PRT((L"TPM device is in deactivated status\n"));
        return NULL;
    }

    return tcg;
}

EFI_STATUS
efi_main (EFI_HANDLE image, EFI_SYSTEM_TABLE *systab)
{
    EFI_LOADED_IMAGE *info;
    EFI_STATUS status;
    EFI_DEVICE_PATH *dp;
    EFI_FILE_HANDLE fs;
    EFI_TCG *tcg;

    InitializeLib(image, systab);

    status = uefi_call_wrapper (BS->HandleProtocol, 3, image, &LoadedImageProtocol, (VOID **) &info);
    if (EFI_ERROR(status)) {
        ERR_PRT((L"image handle does not support LoadedImage protocol"));
        return EFI_LOAD_ERROR;
    }

    Print(L"Loaded at " PTR_FMT " size=%ld bytes code=%d data=%d\n", info->ImageBase, info->ImageSize, info->ImageCodeType, info->ImageDataType);

    dp = DevicePathFromHandle (info->DeviceHandle);
    
    Print(L"Image device      : %s\n", DevicePathToStr(dp));
    Print(L"Image file        : %s\n", DevicePathToStr(info->FilePath));

    fs = LibOpenRoot (info->DeviceHandle);

    if (!fs) {
        ERR_PRT((L"open volume failed"));
    }

    tcg = tcg_interface_check ();

    if (!tcg) {
        ERR_PRT((L"have problem to get a right TCG interface"));
        return EFI_LOAD_ERROR;
    }

    status = measure_file_to_pcr8_and_event_log (fs, tcg, L"\\EFI\\SuSE\\grub.cfg", TRUE);
    if (EFI_ERROR(status)) {
        ERR_PRT((L"measuere config to pcr8 failed"));
        return EFI_LOAD_ERROR;
    }

    status = measure_file_to_pcr8_and_event_log (fs, tcg, L"\\EFI\\SuSE\\vmlinuz-3.0.68-default", FALSE);
    if (EFI_ERROR(status)) {
        ERR_PRT((L"measure kernel to pcr8 failed"));
        return EFI_LOAD_ERROR;
    }

    status = measure_file_to_pcr8_and_event_log (fs, tcg, L"\\EFI\\SuSE\\initrd-3.0.68-default", FALSE);
    if (EFI_ERROR(status)) {
        ERR_PRT((L"measure kernel to pcr8 failed"));
        return EFI_LOAD_ERROR;
    }

    status = uefi_call_wrapper(fs->Close, 1, fs);
    if (EFI_ERROR(status)) {
        ERR_PRT((L"close fs handle failed"));
        return EFI_LOAD_ERROR;
    }

    return EFI_SUCCESS;
}
