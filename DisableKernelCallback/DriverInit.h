#pragma once
#include<stdio.h>
#include<windows.h>
#include"ProcExp.h"

BOOL ServiceStart(char* lpszName, char* lpszPath, BOOL bCreate)
{
	BOOL bRet = FALSE;

	SC_HANDLE hManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (hManager)
	{
		SC_HANDLE hService = NULL;

		if (bCreate)
		{
			// create service for kernel-mode driver
			hService = CreateService(
				hManager, lpszName, lpszName, SERVICE_START | DELETE | SERVICE_STOP,
				SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE,
				lpszPath, NULL, NULL, NULL, NULL, NULL
			);
			if (hService == NULL)
			{
				if (GetLastError() == ERROR_SERVICE_EXISTS)
				{
					// open existing service
					hService = OpenService(hManager, lpszName, SERVICE_START | DELETE | SERVICE_STOP);
				}
			}
		}
		else
		{
			// open existing service
			hService = OpenService(hManager, lpszName, SERVICE_START | DELETE | SERVICE_STOP);
		}

		if (hService)
		{
			// start service
			if (StartService(hService, 0, NULL))
			{
				bRet = TRUE;
			}
			else
			{
				if (GetLastError() == ERROR_SERVICE_ALREADY_RUNNING)
				{
					// service is already started
					bRet = TRUE;
				}
			}

			CloseServiceHandle(hService);
		}

		CloseServiceHandle(hManager);
	}

	return bRet;
}

BOOL ServiceStop(char* lpszName)
{
	BOOL bRet = FALSE;

	SC_HANDLE hManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (hManager)
	{
		// open existing service
		SC_HANDLE hService = OpenService(hManager, lpszName, SERVICE_ALL_ACCESS);
		if (hService)
		{
			SERVICE_STATUS Status;

			// stop service
			if (ControlService(hService, SERVICE_CONTROL_STOP, &Status))
			{
				bRet = TRUE;
			}

			CloseServiceHandle(hService);
		}

		CloseServiceHandle(hManager);
	}

	return bRet;
}

BOOL ServiceRemove(char* lpszName)
{
	BOOL bRet = FALSE;

	SC_HANDLE hManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (hManager)
	{
		// open existing service
		SC_HANDLE hService = OpenService(hManager, lpszName, SERVICE_ALL_ACCESS);
		if (hService)
		{
			// delete service
			if (DeleteService(hService))
			{
				bRet = TRUE;
			}

			CloseServiceHandle(hService);
		}

		CloseServiceHandle(hManager);
	}

	return bRet;
}

BOOL DumpToFile(HANDLE hFile, PVOID Data, DWORD dwDataSize)
{
	BOOL bRet = FALSE;
	DWORD dwWritten = 0;

	// write starting from the beginning of the file
	SetFilePointer(hFile, 0, NULL, FILE_BEGIN);

	if (WriteFile(hFile, Data, dwDataSize, &dwWritten, NULL))
	{
		SetEndOfFile(hFile);
		bRet = TRUE;
	}

	return bRet;
}

BOOL DumpToFile(char* lpszFileName, PVOID Data, DWORD dwDataSize)
{
	BOOL bRet = FALSE;

	// open file for writing
	HANDLE hFile = CreateFile(lpszFileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
	if (hFile != INVALID_HANDLE_VALUE)
	{
		// write data to the file
		bRet = DumpToFile(hFile, Data, dwDataSize);
		CloseHandle(hFile);
	}

	return bRet;
}

//ERROR_ALREADY_EXISTS
void StopDriver()
{
	char szFilePath[MAX_PATH];
	// make driver file path
	char WinDriverName[] = { '\\','d','r','i','v','e','r','s','\\','P','R','O','C','E','X','P','1','5','2','.','S','Y','S','\0' };
	GetSystemDirectory(szFilePath, MAX_PATH);
	strcat_s(szFilePath, WinDriverName);

	// first try to start already existing service
	char WinServiceName[] = { 'P','R','O','C','E','X','P','1','5','2','\0' };
	if (ServiceStart(WinServiceName, szFilePath, TRUE))
	{
		ServiceStop(WinServiceName);
	}

	ServiceRemove(WinServiceName);
}

BOOL DriverInit(void)
{
	StopDriver();
	BOOL bStarted = FALSE;
	char szFilePath[MAX_PATH];

	// make driver file path
	char WinDriverName[] = { '\\','d','r','i','v','e','r','s','\\','P','R','O','C','E','X','P','2','5','2','.','s','y','s','\0' };
	GetSystemDirectory(szFilePath, MAX_PATH);
	strcat_s(szFilePath, WinDriverName);

	// first try to start already existing service
	char WinServiceName[] = {'p','r','o','c','e','p','\0'};
	if (!(bStarted = ServiceStart(WinServiceName, szFilePath, FALSE)))
	{
		// copy driver into the drivers directory
		if (DumpToFile(szFilePath, procExp_sys, sizeof(procExp_sys)))
		{
			// try to create new service
			if (!(bStarted = ServiceStart(WinServiceName, szFilePath, TRUE)))
			{
#ifdef _DEBUG
				printf("ServiceStart failed! GetLastError %d \n",GetLastError());
#endif
				// remove driver
				DeleteFile(szFilePath);
			}
		}
		else
		{
#ifdef _DEBUG
			printf("DumpToFile failed!\n");
#endif
		}
	}

	return bStarted;
}

BOOL DriverUninit(void)
{
	char szFilePath[MAX_PATH];

	// make driver file path
	char WinDriverName[] = { '\\','d','r','i','v','e','r','s','\\','P','R','O','C','E','X','P','2','5','2','.','s','y','s','\0' };
	GetSystemDirectory(szFilePath, MAX_PATH);
	strcat_s(szFilePath, WinDriverName);

	// remove service
	char WinServiceName[] = { 'p','r','o','c','e','p','\0' };
	ServiceStop(WinServiceName);
	ServiceRemove(WinServiceName);

	// remove driver
	DeleteFile(szFilePath);

	return TRUE;
}
