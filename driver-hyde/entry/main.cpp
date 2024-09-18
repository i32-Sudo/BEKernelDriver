#include <ntifs.h>
#include <ntddk.h>
#include <wdm.h>
#include "../clean/clean.hpp"
#include "../kernel/log.h"

#include "../kernel/xor.h"
#include "../kernel/structures.hpp"
#include "../impl/imports.h"

#include "../impl/communication/interface.h"

#include "../impl/scanner.h"
#include "../impl/modules.h"

#include "../requests/get_module_base.cpp"
#include "../requests/read_physical_memory.cpp"
#include "../requests/write_physical_memory.cpp"
#include "../requests/signature_scanner.cpp"
#include "../requests/virtual_allocate.cpp"

#include "../impl/invoked.h"

extern "C" DRIVER_INITIALIZE DriverEntry;

//extern void NTAPI initiliaze_sys(void*);



EXTERN_C
PLIST_ENTRY PsLoadedModuleList;

extern void NTAPI initiliaze_sys(void*) {

}

typedef struct _KLDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	PVOID ExceptionTable;
	ULONG ExceptionTableSize;
	// ULONG padding on IA64
	PVOID GpValue;
	/*PNON_PAGED_DEBUG_INFO*/ PVOID NonPagedDebugInfo;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT __Unused5;
	PVOID SectionPointer;
	ULONG CheckSum;
	// ULONG padding on IA64
	PVOID LoadedImports;
	PVOID PatchInformation;
} KLDR_DATA_TABLE_ENTRY, * PKLDR_DATA_TABLE_ENTRY;

void CleanDriverSys(UNICODE_STRING driver_int, ULONG timeDateStamp) {
	if (clear::clearCache(driver_int, timeDateStamp) == 0) {
		log(_("PiDDB Cache Found and Cleared!"));
	}
	else {
		log(_("PiDDB Non-Zero"));
	}
	if (clear::clearHashBucket(driver_int) == 0) {
		log(_("HashBucket Found and Cleared!"));
	}
	else {
		log(_("HashBucket Non-Zero"));
	}
	if (clear::CleanMmu(driver_int) == 0) {
		log(_("MMU/MML Found and Cleaned!"));
	}
	else {
		log(_("MMU/MML Non-Zero"));
	}
}


_declspec(noinline) auto manual_mapped_entry(
	PDRIVER_OBJECT driver_obj,
	PUNICODE_STRING registry_path) -> long
{
	UNREFERENCED_PARAMETER(registry_path);

	/* Please use custom shellcode/asm for the Hook, This can be signature scanned by BE / EAC */
	uint8_t execute[] = {

		0x48, 0xB8, // -> mov, rax
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // -> address
		0xFF, 0xE0 // -> jmp rax

	};

	*reinterpret_cast<void**>(&execute[2]) = &vortex::io_dispatch;
	if (!NT_SUCCESS(modules::write_address(globals::entry_point, execute, sizeof(execute), true)))
		return driver::status::failed_sanity_check;

	*reinterpret_cast<void**>(&execute[2]) = &vortex::io_close;
	auto create_close = (globals::cave_base + sizeof(execute));
	if (!NT_SUCCESS(modules::write_address(create_close, execute, sizeof(execute), true)))
		return driver::status::failed_sanity_check;

	UNICODE_STRING device;
	UNICODE_STRING dos_device;

	qtx_import(RtlInitUnicodeString)(&device, _(DEVICE_NAME));
	qtx_import(RtlInitUnicodeString)(&dos_device, _(DOS_NAME));

	PDEVICE_OBJECT device_obj = nullptr;
	auto status = qtx_import(IoCreateDevice)(driver_obj,
		0,
		&device,
		FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_SECURE_OPEN,
		false,
		&device_obj);

	if (NT_SUCCESS(status))
	{
		SetFlag(driver_obj->Flags, DO_BUFFERED_IO);

		driver_obj->MajorFunction[IRP_MJ_CREATE] = reinterpret_cast<PDRIVER_DISPATCH>(&vortex::io_close);
		driver_obj->MajorFunction[IRP_MJ_CLOSE] = reinterpret_cast<PDRIVER_DISPATCH>(&vortex::io_close);
		driver_obj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = reinterpret_cast<PDRIVER_DISPATCH>(globals::entry_point);
		driver_obj->DriverUnload = nullptr;

		ClearFlag(device_obj->Flags, DO_DIRECT_IO);
		ClearFlag(device_obj->Flags, DO_DEVICE_INITIALIZING);

		status = qtx_import(IoCreateSymbolicLink)(&dos_device, &device);
		if (!NT_SUCCESS(status)) {
			qtx_import(IoDeleteDevice)(device_obj);
		}

	}

	return status;
}

_declspec(noinline) auto initialize_hook() -> driver::status
{

	globals::ntos_image_base = modules::get_ntos_base_address();
	if (!globals::ntos_image_base) {
		print_dbg(_(" [sanity] -> failed to get ntoskrnl image.\n"));
		return driver::status::failed_sanity_check;
	}

	auto io_create_driver_t = reinterpret_cast<void*>(modules::get_kernel_export(globals::ntos_image_base, _("IoCreateDriver")));
	if (!io_create_driver_t) {
		print_dbg(_(" [sanity] -> failed to get IoCreateDriver.\n"));
		return driver::status::failed_sanity_check;
	}

	*reinterpret_cast<void**>(&globals::io_create_driver) = io_create_driver_t;

	/*
	const auto random = modules::get_random( );
	switch ( random % 2 )
	{
	case 0:
		break;
	case 1:
		break;
	}*/

	const auto target_module = modules::get_kernel_module(_("")); /* Find your own module that is not PG Protected */
	if (!target_module) {
		print_dbg(_(" [sanity] -> failed to find target module.\n"));
		return driver::status::failed_sanity_check;
	}

	BYTE section_char[] = { '.', 't', 'e', 'x', 't', '\0' };
	globals::cave_base = modules::find_pattern(target_module,
		_(""), /* Find your own Signature */
		_("")); /* Find your own Mask */

	// get code cave a different way please
	globals::cave_base = globals::cave_base - 0x30;

	crt::kmemset(&section_char, 0, sizeof(section_char));

	/* Please use custom shellcode/asm for the Hook, This can be signature scanned by BE / EAC */
	uint8_t execute[] = {

		0x48, 0xB8, // -> mov, rax
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // -> address
		0xFF, 0xE0 // -> jmp rax

	};

	globals::entry_point = globals::cave_base;

	*reinterpret_cast<void**>(&execute[2]) = &manual_mapped_entry;
	modules::write_address(
		globals::entry_point,
		execute,
		sizeof(execute),
		true
	);

	return driver::status::successful_operation;
}

_declspec(noinline) auto initialize_ioctl() -> driver::status
{

	/////////////// Original Function QWORD
	const auto result = globals::io_create_driver(
		nullptr,
		reinterpret_cast<DRIVER_INITIALIZE*>(globals::entry_point)
	);
	if (!NT_SUCCESS(result)) {
		return driver::status::failed_sanity_check;
	}

	return driver::status::successful_operation;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////

extern "C" NTSTATUS OEPDriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
	NTSTATUS status = STATUS_SUCCESS;
	KeEnterGuardedRegion();

	// status = STATUS_SUCCESS;
	if (initialize_hook() != driver::status::successful_operation)
		return driver::status::failed_intialization;
	// 
	// // if driver is signed or loaded using dse
	// // if ( initialize_dkom( ) != driver::status::successful_operation )
	// // 	return driver::status::failed_intialization;
	//

	if (initialize_ioctl() != driver::status::successful_operation)
		return driver::status::failed_intialization;

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, _(" - OEP Started"));

	//////////////////////////////////////////////////////////////////////////////////////////////////////////

	/*
	0x5284EAC3 - iqvw64e.sys
	0xBF8A5E6A - srv2.sys | 2071-10-31 14:26:34
	0x63EF9904 - DriverKL.sys | Feb 16 2023 6:31
	0x611AB60D - PROCEXP152.SYS | August 16, 2021 7:01:33 PM
	*/

	// Loader Drivers @ Host Driver
	CleanDriverSys(UNICODE_STRING(RTL_CONSTANT_STRING(L"DriverKL.sys")), 0x63EF9904); /* Cheat Driver (Current Drivr) */
	CleanDriverSys(UNICODE_STRING(RTL_CONSTANT_STRING(L"srv2.sys")), 0xBF8A5E6A); /* GDRV Driver */
	CleanDriverSys(UNICODE_STRING(RTL_CONSTANT_STRING(L"PROCEXP152.sys")), 0x611AB60D); /* Vulnereable Driver */

	KeLeaveGuardedRegion();
	return STATUS_SUCCESS;
}

/* Fake OEP */
extern "C" NTSTATUS driver_entry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, _(" - Driver Started"));

	return OEPDriverEntry(DriverObject, RegistryPath);
}
