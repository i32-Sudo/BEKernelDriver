#pragma once
#include<stdio.h>
#include<windows.h>
#include<ntstatus.h>
#include <iostream>

#define SystemExtendedHandleInformation 64
#define PH_LARGE_BUFFER_SIZE (256 * 1024 * 1024)
typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
{
	PVOID Object;
	ULONG_PTR UniqueProcessId;
	ULONG_PTR HandleValue;
	ULONG GrantedAccess;
	USHORT CreatorBackTraceIndex;
	USHORT ObjectTypeIndex;
	ULONG HandleAttributes;
	ULONG Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;
typedef struct _SYSTEM_HANDLE_INFORMATION_EX
{
	ULONG_PTR NumberOfHandles;
	ULONG_PTR Reserved;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, * PSYSTEM_HANDLE_INFORMATION_EX;
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
typedef LONG(WINAPI* PNtQuerySystemInformation) (int SystemInformationClass, OUT PVOID SystemInformation, IN ULONG SystemInformationLength, OUT ULONG* pReturnLength OPTIONAL);
PNtQuerySystemInformation NtQuerySystemInformation = NULL;
typedef enum _OBJECT_INFORMATION_CLASS {
	ObjectBasicInformation,
	ObjectNameInformation,
	ObjectTypeInformation,
	ObjectAllInformation,
	ObjectDataInformation
} OBJECT_INFORMATION_CLASS, * POBJECT_INFORMATION_CLASS;
typedef struct {
	USHORT Length;
	USHORT MaxLen;
	USHORT* Buffer;
}UNICODE_STRING, * PUNICODE_STRING;
typedef struct _OBJECT_NAME_INFORMATION {
	UNICODE_STRING          Name;
	WCHAR                   NameBuffer[0];
} OBJECT_NAME_INFORMATION, * POBJECT_NAME_INFORMATION;
typedef NTSTATUS(WINAPI* PNtQueryObject)(HANDLE Handle, OBJECT_INFORMATION_CLASS ObjectInformationClass, PVOID ObjectInformation, ULONG ObjectInformationLength, PULONG ReturnLength);
PNtQueryObject 	NtQueryObject = NULL;
typedef enum _SECTION_INHERIT {
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT;
typedef NTSTATUS(WINAPI* PNtMapViewOfSection)(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER  SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect);
PNtMapViewOfSection  NtMapViewOfSection = NULL;
typedef VOID(WINAPI* PRtlInitUnicodeString)(PUNICODE_STRING DestinationString, PCWSTR SourceString);
PRtlInitUnicodeString  RtlInitUnicodeString = NULL;
typedef const UNICODE_STRING* PCUNICODE_STRING;
typedef NTSTATUS(WINAPI* PLdrLoadDll)(PCWSTR DllPath, PULONG DllCharacteristics, PCUNICODE_STRING DllName, PVOID* DllHandle);
PLdrLoadDll   LdrLoadDll = NULL;

#pragma pack(1) 
typedef struct _PAGEFORMAT
{
	ULONG64 offset : 12;
	ULONG64 pte : 9;
	ULONG64 pde : 9;
	ULONG64 ppe : 9;
	ULONG64 pxe : 9;
	ULONG64 padding : 16;
}PAGEFORMAT, * PPAGEFORMAT;
#pragma pack() 


typedef NTSTATUS(WINAPI* PRtlGetVersion)(PRTL_OSVERSIONINFOW lpVersionInformation);
PRtlGetVersion 	RtlGetVersion = NULL;
#define NT_ERROR(Status)  ((ULONG)(Status) >> 30 == 3)


typedef struct _RTL_PROCESS_MODULE_INFORMATION {
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULE_INFORMATION_EX {
	USHORT NextOffset;
	RTL_PROCESS_MODULE_INFORMATION BaseInfo;
	ULONG ImageChecksum;
	ULONG TimeDateStamp;
	PVOID DefaultBase;
} RTL_PROCESS_MODULE_INFORMATION_EX, * PRTL_PROCESS_MODULE_INFORMATION_EX;

typedef struct _RTL_PROCESS_MODULES {
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;
#define SystemModuleInformationEx  77
#define SystemModuleInformation  11
#define M_ALLOC(_size_) LocalAlloc(LMEM_FIXED | LMEM_ZEROINIT, (_size_))
#define M_FREE(_addr_) LocalFree((_addr_))
#define RVATOVA(_base_, _offset_) ((PUCHAR)(_base_) + (ULONG)(_offset_))
typedef struct _KSYSTEM_TIME {
	ULONG LowPart;
	LONG High1Time;
	LONG High2Time;
} KSYSTEM_TIME, * PKSYSTEM_TIME;
typedef enum _NT_PRODUCT_TYPE {
	NtProductWinNt = 1,
	NtProductLanManNt,
	NtProductServer
} NT_PRODUCT_TYPE, * PNT_PRODUCT_TYPE;
#define PROCESSOR_FEATURE_MAX 64
typedef enum _ALTERNATIVE_ARCHITECTURE_TYPE {
	StandardDesign,                 // None == 0 == standard design
	NEC98x86,                       // NEC PC98xx series on X86
	EndAlternatives                 // past end of known alternatives
} ALTERNATIVE_ARCHITECTURE_TYPE;
typedef struct _KUSER_SHARED_DATA {

	ULONG TickCountLowDeprecated;
	ULONG TickCountMultiplier;

	volatile KSYSTEM_TIME InterruptTime;
	volatile KSYSTEM_TIME SystemTime;
	volatile KSYSTEM_TIME TimeZoneBias;

	USHORT ImageNumberLow;
	USHORT ImageNumberHigh;

	WCHAR NtSystemRoot[260];

	ULONG MaxStackTraceDepth;
	ULONG CryptoExponent;
	ULONG TimeZoneId;
	ULONG LargePageMinimum;

	union {
		ULONG Reserved2[7];
		struct {
			ULONG AitSamplingValue;
			ULONG AppCompatFlag;
			struct {
				ULONG LowPart;
				ULONG HighPart;
			} RNGSeedVersion;
			ULONG GlobalValidationRunlevel;
			LONG TimeZoneBiasStamp;
			ULONG NtBuildNumber;
		};
	};

	NT_PRODUCT_TYPE NtProductType;
	BOOLEAN ProductTypeIsValid;
	UCHAR Reserved0[1];
	USHORT NativeProcessorArchitecture;

	ULONG NtMajorVersion;
	ULONG NtMinorVersion;

	BOOLEAN ProcessorFeatures[PROCESSOR_FEATURE_MAX];
	ULONG Reserved1;
	ULONG Reserved3;
	volatile ULONG TimeSlip;
	ALTERNATIVE_ARCHITECTURE_TYPE AlternativeArchitecture;
	ULONG AltArchitecturePad;
	LARGE_INTEGER SystemExpirationDate;
	ULONG SuiteMask;
	BOOLEAN KdDebuggerEnabled;

	union {
		UCHAR MitigationPolicies;
		struct {
			UCHAR NXSupportPolicy : 2;
			UCHAR SEHValidationPolicy : 2;
			UCHAR CurDirDevicesSkippedForDlls : 2;
			UCHAR Reserved : 2;
		};
	};

	UCHAR Reserved6[2];

	volatile ULONG ActiveConsoleId;
	volatile ULONG DismountCount;
	ULONG ComPlusPackage;
	ULONG LastSystemRITEventTickCount;
	ULONG NumberOfPhysicalPages;
	BOOLEAN SafeBootMode;
	UCHAR VirtualizationFlags;
	UCHAR Reserved12[2];

	union {
		ULONG SharedDataFlags;
		struct {
			ULONG DbgErrorPortPresent : 1;
			ULONG DbgElevationEnabled : 1;
			ULONG DbgVirtEnabled : 1;
			ULONG DbgInstallerDetectEnabled : 1;
			ULONG DbgLkgEnabled : 1;
			ULONG DbgDynProcessorEnabled : 1;
			ULONG DbgConsoleBrokerEnabled : 1;
			ULONG DbgSecureBootEnabled : 1;
			ULONG DbgMultiSessionSku : 1;
			ULONG DbgMultiUsersInSessionSku : 1;
			ULONG DbgStateSeparationEnabled : 1;
			ULONG SpareBits : 21;
		};
	};
	ULONG DataFlagsPad[1];
	ULONGLONG TestRetInstruction;
	LONGLONG QpcFrequency;

	ULONG SystemCall;
	ULONG SystemCallPad0;

	ULONGLONG SystemCallPad[2];

	union {
		volatile KSYSTEM_TIME TickCount;
		volatile ULONG64 TickCountQuad;
		struct {
			ULONG ReservedTickCountOverlay[3];
			ULONG TickCountPad[1];
		};
	};

	ULONG Cookie;
	ULONG CookiedPad[1];

	LONGLONG ConsoleSessionForegroundProcessId;

	ULONGLONG TimeUpdateLock;
	ULONGLONG BaselineSystemTimeQpc;
	ULONGLONG BaselineInterruptTimeQpc;
	ULONGLONG QpcSystemTimeIncrement;
	ULONGLONG QpcInterruptTimeIncrement;
	UCHAR QpcSystemTimeIncrementShift;
	UCHAR QpcInterruptTimeIncrementShift;
	USHORT UnparkedProcessorCount;

	ULONG EnclaveFeatureMask[4];
	union {
		ULONG Reserved8;
		ULONG TelemetryCoverageRound;
	};

	USHORT UserModeGlobalLogger[16];

	ULONG ImageFileExecutionOptions;
	ULONG LangGenerationCount;
	ULONGLONG Reserved4;

	volatile ULONG64 InterruptTimeBias;
	volatile ULONG64 QpcBias;

	ULONG ActiveProcessorCount;
	volatile UCHAR ActiveGroupCount;
	UCHAR Reserved9;

	union {
		USHORT QpcData;
		struct {
			UCHAR QpcBypassEnabled : 1;
			UCHAR QpcShift : 1;
		};
	};

	LARGE_INTEGER TimeZoneBiasEffectiveStart;
	LARGE_INTEGER TimeZoneBiasEffectiveEnd;

	XSTATE_CONFIGURATION XState;

	KSYSTEM_TIME FeatureConfigurationChangeStamp;
	ULONG Spare;

} KUSER_SHARED_DATA, * PKUSER_SHARED_DATA;
#define MM_SHARED_USER_DATA_VA      0x000000007FFE0000
#define USER_SHARED_DATA ((KUSER_SHARED_DATA * const)MM_SHARED_USER_DATA_VA)

// max arguments for KfCall(): 4 over the registers and 9 over the stack
#define MAX_ARGS (4 + 9)

// convert KfCall() call arguments
#define KF_ARG(_val_) ((PVOID)(_val_))

// convert KfCall() return value
#define KF_RET(_val_) ((PVOID *)(_val_))

typedef enum _KTHREAD_STATE
{
	Initialized,
	Ready,
	Running,
	Standby,
	Terminated,
	Waiting,
	Transition,
	DeferredReady,
	GateWaitObsolete,
	WaitingForProcessInSwap,
	MaximumThreadState

} KTHREAD_STATE,
* PKTHREAD_STATE;

typedef enum _KWAIT_REASON
{
	Executive,
	FreePage,
	PageIn,
	PoolAllocation,
	DelayExecution,
	Suspended,
	UserRequest,
	WrExecutive,
	WrFreePage,
	WrPageIn,
	WrPoolAllocation,
	WrDelayExecution,
	WrSuspended,
	WrUserRequest,
	WrEventPair,
	WrQueue,
	WrLpcReceive,
	WrLpcReply,
	WrVirtualMemory,
	WrPageOut,
	WrRendezvous,
	WrKeyedEvent,
	WrTerminated,
	WrProcessInSwap,
	WrCpuRateControl,
	WrCalloutStack,
	WrKernel,
	WrResource,
	WrPushLock,
	WrMutex,
	WrQuantumEnd,
	WrDispatchInt,
	WrPreempted,
	WrYieldExecution,
	WrFastMutex,
	WrGuardedMutex,
	WrRundown,
	WrAlertByThreadId,
	WrDeferredPreempt,
	WrPhysicalFault,
	MaximumWaitReason

} KWAIT_REASON,
* PKWAIT_REASON;

typedef struct _CLIENT_ID
{
	HANDLE UniqueProcess;
	HANDLE UniqueThread;

} CLIENT_ID,
* PCLIENT_ID;

typedef struct _SYSTEM_THREAD_INFORMATION
{
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	ULONG WaitTime;
	PVOID StartAddress;
	CLIENT_ID ClientId;
	ULONG Priority;
	LONG BasePriority;
	ULONG ContextSwitches;
	KTHREAD_STATE ThreadState;
	KWAIT_REASON WaitReason;

} SYSTEM_THREAD_INFORMATION,
* PSYSTEM_THREAD_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFORMATION
{
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER WorkingSetPrivateSize;
	ULONG HardFaultCount;
	ULONG NumberOfThreadsHighWatermark;
	ULONGLONG CycleTime;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	ULONG BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	ULONG_PTR UniqueProcessKey;
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	LARGE_INTEGER ReadTransferCount;
	LARGE_INTEGER WriteTransferCount;
	LARGE_INTEGER OtherTransferCount;
	SYSTEM_THREAD_INFORMATION Threads[1];

} SYSTEM_PROCESS_INFORMATION,
* PSYSTEM_PROCESS_INFORMATION;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
	USHORT UniqueProcessId;
	USHORT CreatorBackTraceIndex;
	UCHAR ObjectTypeIndex;
	UCHAR HandleAttributes;
	USHORT HandleValue;
	PVOID Object;
	ULONG GrantedAccess;

} SYSTEM_HANDLE_TABLE_ENTRY_INFO,
* PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG NumberOfHandles;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];

} SYSTEM_HANDLE_INFORMATION,
* PSYSTEM_HANDLE_INFORMATION;

#define OBJ_INHERIT                     0x00000002
#define OBJ_PERMANENT                   0x00000010
#define OBJ_EXCLUSIVE                   0x00000020
#define OBJ_CASE_INSENSITIVE            0x00000040
#define OBJ_OPENIF                      0x00000080
#define OBJ_OPENLINK                    0x00000100
#define OBJ_VALID_ATTRIBUTES            0x000001F2
#define OBJ_KERNEL_HANDLE               0x00000200

typedef struct _OBJECT_ATTRIBUTES
{
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;
	PVOID SecurityQualityOfService;

} OBJECT_ATTRIBUTES,
* POBJECT_ATTRIBUTES;

#define InitializeObjectAttributes(_ptr_, _name_, _attr_, _root_, _sd_)     \
                                                                            \
    {                                                                       \
        (_ptr_)->Length = sizeof(OBJECT_ATTRIBUTES);                        \
        (_ptr_)->RootDirectory = (_root_);                                  \
        (_ptr_)->Attributes = (_attr_);                                     \
        (_ptr_)->ObjectName = (_name_);                                     \
        (_ptr_)->SecurityDescriptor = (_sd_);                               \
        (_ptr_)->SecurityQualityOfService = NULL;                           \
    }


#pragma pack(1)
typedef struct _OB_CALLBACK
{
	LIST_ENTRY ListEntry;
	ULONGLONG Unknown;
	HANDLE ObHandle;
	PVOID ObTypeAddr;
	PVOID	PreCall;
	PVOID PostCall;
}OB_CALLBACK, * POB_CALLBACK;
#pragma pack()

typedef struct _CM_NOTIFY_ENTRY
{
	LIST_ENTRY  ListEntryHead;
	ULONG   UnKnown1;
	ULONG   UnKnown2;
	LARGE_INTEGER Cookie;
	PVOID   Context;
	PVOID   Function;
}CM_NOTIFY_ENTRY, * PCM_NOTIFY_ENTRY;

typedef enum _POOL_TYPE {
	NonPagedPool,
	NonPagedPoolExecute = NonPagedPool,
	PagedPool,
	NonPagedPoolMustSucceed = NonPagedPool + 2,
	DontUseThisType,
	NonPagedPoolCacheAligned = NonPagedPool + 4,
	PagedPoolCacheAligned,
	NonPagedPoolCacheAlignedMustS = NonPagedPool + 6,
	MaxPoolType,
	NonPagedPoolBase = 0,
	NonPagedPoolBaseMustSucceed = NonPagedPoolBase + 2,
	NonPagedPoolBaseCacheAligned = NonPagedPoolBase + 4,
	NonPagedPoolBaseCacheAlignedMustS = NonPagedPoolBase + 6,
	NonPagedPoolSession = 32,
	PagedPoolSession = NonPagedPoolSession + 1,
	NonPagedPoolMustSucceedSession = PagedPoolSession + 1,
	DontUseThisTypeSession = NonPagedPoolMustSucceedSession + 1,
	NonPagedPoolCacheAlignedSession = DontUseThisTypeSession + 1,
	PagedPoolCacheAlignedSession = NonPagedPoolCacheAlignedSession + 1,
	NonPagedPoolCacheAlignedMustSSession = PagedPoolCacheAlignedSession + 1,
	NonPagedPoolNx = 512,
	NonPagedPoolNxCacheAligned = NonPagedPoolNx + 4,
	NonPagedPoolSessionNx = NonPagedPoolNx + 32,

} POOL_TYPE;

typedef ULONG FLT_OPERATION_REGISTRATION_FLAGS;
typedef struct _FLT_OPERATION_REGISTRATION {

	UCHAR MajorFunction;
	FLT_OPERATION_REGISTRATION_FLAGS Flags;
	PVOID PreOperation;
	PVOID PostOperation;
	PVOID Reserved1;
} FLT_OPERATION_REGISTRATION, * PFLT_OPERATION_REGISTRATION;

#define IRP_MJ_OPERATION_END                        ((UCHAR)0x80)
#define IRP_MJ_MAXIMUM_FUNCTION         0x1b


typedef struct _FLT_SERVER_PORT_OBJECT
{
	LIST_ENTRY FilterLink;
	PVOID ConnectNotify;
	PVOID DisconnectNotify;
	PVOID MessageNotify;
	PVOID Filter;
	PVOID Cookie;
	ULONG Flags;
	LONG NumberOfConnections;
	LONG MaxConnections;
} FLT_SERVER_PORT_OBJECT, * PFLT_SERVER_PORT_OBJECT;
