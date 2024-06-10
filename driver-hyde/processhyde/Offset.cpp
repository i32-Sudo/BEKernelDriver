#include <ntddk.h>
#include "Offset.h"

// ntoskrnl.exe는 윈도우 버전과 관계없이 현재까지는 항상 다음과 같은 정보를 가졌음.
// ImageName : System
// PID : 4
// PLIST_ENTRY = PID + sizeof(PID)

extern "C"
ULONG CalcPIDOffset()
{
    PEPROCESS peprocess = IoGetCurrentProcess();
    HANDLE pid = PsGetCurrentProcessId();
    PLIST_ENTRY list = NULL;
    int i;

    for (i = 0; i < PAGE_SIZE; i += 4)
    {
        if (*(PHANDLE)((PCHAR)peprocess + i) == pid)
        {
            // PLIST_ENTRY는 PID 다음에 위치해있음.
            list = (PLIST_ENTRY)((unsigned char*)peprocess + i + sizeof(HANDLE));
            
            // 유효한 주소인지 확인한다.
            if (MmIsAddressValid(list))
            {
                // 정상적으로 연결된 리스트인지 확인 후 PID 주소를 반환한다.
                if (list == list->Flink->Blink)
                {
                    return i;
                }
            }
        }
    }

    return 0;
}

extern "C"
ULONG CalcProcessNameOffset()
{
    // ntoskrn.exe 의 EPROCESS 구조체 획득
    PEPROCESS ntosKrnl = PsInitialSystemProcess;
    int i = 0;

    for (i = 0; i < PAGE_SIZE; i++)
    {
        if (RtlCompareMemory((PCHAR)ntosKrnl + i, "System", 6) == 6)
        {
            return i;
        }
    }

    return 0;
}