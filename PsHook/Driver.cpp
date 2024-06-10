#include <ntifs.h>
#include <ntddk.h>
#include <ntimage.h>
#include <windef.h>

typedef struct _CALLBACK_ROUTINE_BLOCK
{
	EX_RUNDOWN_REF RundownProtect;
	PEX_CALLBACK_FUNCTION Function;
	PVOID Context;
} CALLBACK_ROUTINE_BLOCK, * PCALLBACK_ROUTINE_BLOCK;

typedef PCALLBACK_ROUTINE_BLOCK(NTAPI* ExAllocateCallBackType)(PVOID, UINT32);
typedef BOOL(NTAPI* ExCompareExchangeCallBackType)(PVOID, PVOID, ULONG);
ExAllocateCallBackType ExAllocateCallBack = nullptr;
ExCompareExchangeCallBackType ExCompareExchangeCallBack = nullptr;

#ifdef __cplusplus
extern "C"
{
#endif

	typedef struct _SYSTEM_MODULE
	{
		ULONG_PTR Reserved[2];
		PVOID Base;
		ULONG Size;
		ULONG Flags;
		USHORT Index;
		USHORT Unknown;
		USHORT LoadCount;
		USHORT ModuleNameOffset;
		CHAR ImageName[256];
	} SYSTEM_MODULE, * PSYSTEM_MODULE;

	typedef struct _SYSTEM_MODULE_INFORMATION
	{
		ULONG_PTR ulModuleCount;
		SYSTEM_MODULE Modules[1];
	} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

	NTSTATUS
		NTAPI
		ZwQuerySystemInformation(
			DWORD32 systemInformationClass,
			PVOID systemInformation,
			ULONG systemInformationLength,
			PULONG returnLength);

#ifdef __cplusplus
}
#endif

bool get_module_base_address(const char* name, unsigned long long& addr, unsigned long& size)
{
	unsigned long need_size = 0;
	ZwQuerySystemInformation(11, &need_size, 0, &need_size);
	if (need_size == 0) return false;

	const unsigned long tag = 'VMON';
	PSYSTEM_MODULE_INFORMATION sys_mods = (PSYSTEM_MODULE_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, need_size, tag);
	if (sys_mods == 0) return false;

	NTSTATUS status = ZwQuerySystemInformation(11, sys_mods, need_size, 0);
	if (!NT_SUCCESS(status))
	{
		ExFreePoolWithTag(sys_mods, tag);
		return false;
	}

	for (unsigned long long i = 0; i < sys_mods->ulModuleCount; i++)
	{
		PSYSTEM_MODULE mod = &sys_mods->Modules[i];
		if (strstr(mod->ImageName, name))
		{
			addr = (unsigned long long)mod->Base;
			size = (unsigned long)mod->Size;
			break;
		}
	}

	ExFreePoolWithTag(sys_mods, tag);
	return true;
}

bool pattern_check(const char* data, const char* pattern, const char* mask)
{
	size_t len = strlen(mask);

	for (size_t i = 0; i < len; i++)
	{
		if (data[i] == pattern[i] || mask[i] == '?')
			continue;
		else
			return false;
	}

	return true;
}

unsigned long long find_pattern(unsigned long long addr, unsigned long size, const char* pattern, const char* mask)
{
	size -= (unsigned long)strlen(mask);

	for (unsigned long i = 0; i < size; i++)
	{
		if (pattern_check((const char*)addr + i, pattern, mask))
			return addr + i;
	}

	return 0;
}

unsigned long long find_pattern_image(unsigned long long addr, const char* pattern, const char* mask)
{
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)addr;
	if (dos->e_magic != IMAGE_DOS_SIGNATURE)
		return 0;

	PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(addr + dos->e_lfanew);
	if (nt->Signature != IMAGE_NT_SIGNATURE)
		return 0;

	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);

	for (unsigned short i = 0; i < nt->FileHeader.NumberOfSections; i++)
	{
		PIMAGE_SECTION_HEADER p = &section[i];

		if (strstr((const char*)p->Name, ".text") || 'EGAP' == *reinterpret_cast<int*>(p->Name))
		{
			unsigned long long res = find_pattern(addr + p->VirtualAddress, p->Misc.VirtualSize, pattern, mask);
			if (res) return res;
		}
	}

	return 0;
}


NTSTATUS ChangeMemoryProtection(PVOID baseAddress, ULONG size, ULONG newProtection) {
	PMDL mdl = NULL;
	NTSTATUS status = STATUS_SUCCESS;

	__try {
		// Allocate MDL
		mdl = IoAllocateMdl(baseAddress, size, FALSE, FALSE, NULL);
		if (!mdl) {
			status = STATUS_INSUFFICIENT_RESOURCES;
			__leave;
		}

		// Build MDL for non-paged pool
		MmBuildMdlForNonPagedPool(mdl);

		// Change memory protection
		status = MmProtectMdlSystemAddress(mdl, newProtection);

		if (!NT_SUCCESS(status)) {
			DbgPrint("MmProtectMdlSystemAddress failed: 0x%x\n", status);
			__leave;
		}

	}
	__finally {
		// Cleanup
		if (mdl) {
			IoFreeMdl(mdl);
		}
	}

	return status;
}

VOID PsCreateProcessNotifyCallback(
	IN HANDLE ParentId,
	IN HANDLE ProcessId,
	IN BOOLEAN Create)
{
	DbgPrint("PsCreateProcessNotifyCallback Called");
}



void enum_create_process_notify_routine()
{
	unsigned long long address = 0;
	unsigned long size = 0;
	if (get_module_base_address("ntoskrnl.exe", address, size) == false) return;
	DbgPrintEx(0, 0, "[%s] ntoskrnl address : %p, size : %lld \n", __FUNCTION__, address, size);

	void* PspCreateProcessNotifyRoutine = (void*)find_pattern_image(address,
		"\x4C\x8D\x2D\x00\x00\x00\x00\x48\x8D\x0C\xDD\x00\x00\x00\x00\x45\x33\xC0\x49\x03\xCD\x48\x8B\xD7\xE8\x00\x00\x00\x00\x84\xC0",
		"xxx????xxxx????xxxxxxxxxx????xx");

	if (PspCreateProcessNotifyRoutine == nullptr) {
		DbgPrint("Unable to Find PspCreateProcessNotifyRoutine");
		return;
	}

	for (unsigned int i = 0; i < 64; i++)
	{
		void* routine_address = *(void**)((unsigned char*)PspCreateProcessNotifyRoutine + sizeof(void*) * i);
		routine_address = (void*)((unsigned long long)routine_address & 0xfffffffffffffff8);
		if (MmIsAddressValid(routine_address))
		{
			routine_address = *(void**)routine_address;
			DbgPrintEx(0, 0, "[%s] [%d] routine address %p\n", __FUNCTION__, i, routine_address);
		}
	}

	return;
}

VOID
UnloadDriver
(
	IN PDRIVER_OBJECT DriverObject
)
{
	UNREFERENCED_PARAMETER(DriverObject);
}


EXTERN_C
NTSTATUS
DriverEntry(
	IN PDRIVER_OBJECT DriverObject,
	IN PUNICODE_STRING RegistryPath)
{
	DriverObject->DriverUnload = UnloadDriver;

	enum_create_process_notify_routine();

	return STATUS_UNSUCCESSFUL;
}