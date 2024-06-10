#include "global.h"
#include "binary/dropper.h"
#include <Windows.h>
#include <iostream>
#include <algorithm>

const wchar_t* DriverPath = L"C:\\Windows\\System32\\Drivers\\gdrv.sys";

/*

    Only for use on battleye, and some EAC Games.
    Credits for Loader -> https://github.com/zer0condition/GDRVLoader

*/

int wmain(int argc, wchar_t** argv)
{
    if (argc < 3) {
        std::wcout << L"Invalid arguments. Usage: " << argv[0] << L" <operation> <TargetDriver.sys>" << std::endl;
        return false;
    }

    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    // argv[1] is the operation (LOAD or UNLOAD)
    std::wstring operation = argv[1];
    std::transform(operation.begin(), operation.end(), operation.begin(), ::toupper);

    if (operation == L"LOAD")
    {
        if (DropDriverFromBytes(DriverPath))
        {
            // Load driver
            Status = WindLoadDriver((PWCHAR)DriverPath, argv[2], FALSE);

            if (NT_SUCCESS(Status))
                std::wcout << L"Driver loaded successfully" << std::endl;

            DeleteFile(DriverPath);
        }
    }
    else if (operation == L"UNLOAD")
    {
        // Unload driver
        Status = WindUnloadDriver(argv[2], 0);
        if (NT_SUCCESS(Status))
            std::wcout << L"Driver unloaded successfully" << std::endl;
    }
    else
    {
        std::wcout << L"Invalid operation. Supported operations: LOAD, UNLOAD" << std::endl;
        return false;
    }

    if (!NT_SUCCESS(Status))
        std::wcout << L"Error: " << std::hex << Status << std::endl;

    return true;
}