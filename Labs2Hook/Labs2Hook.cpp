#include "Labs2Hook.h"
#include <detours.h>


HANDLE WINAPI MyCreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
    int index = strlen(lpFileName);
    for (; index >= 0; index--)
        if (lpFileName[index] == '\\')
            break;
    index++;

    if (!strcmp(lpFileName + index, FileOrFunc))
        return INVALID_HANDLE_VALUE;
    
    return origCreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

HANDLE WINAPI MyCreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
    int index = wcslen(lpFileName);
    for (; index >= 0; index--)
        if (lpFileName[index] == '\\')
            break;
    index++;

    if (!wcscmp(lpFileName+ index, FileOrFuncW))
        return INVALID_HANDLE_VALUE;

    return origCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

HANDLE WINAPI MyFindFirstFileA(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData)
{
    int index = strlen(lpFileName);
    for (; index >= 0; index--)
        if (lpFileName[index] == '\\')
            break;
    index++;

    if (!strcmp(lpFileName + index, FileOrFunc))
        return INVALID_HANDLE_VALUE;
    
    return origFindFirstFileA(lpFileName, lpFindFileData);
}

HANDLE WINAPI MyFindFirstFileW(LPCWSTR lpFileName, LPWIN32_FIND_DATA lpFindFileData)
{
    int index = wcslen(lpFileName);
    for (; index >= 0; index--)
        if (lpFileName[index] == '\\')
            break;
    index++;

    if (!wcscmp(lpFileName + index, FileOrFuncW))
        return INVALID_HANDLE_VALUE;

    return origFindFirstFileW(lpFileName, lpFindFileData);
}

BOOL WINAPI MyFindNextFileA(HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData)
{
    bool ret = origFindNextFileA(hFindFile, lpFindFileData);
    if (!strcmp(lpFindFileData->cFileName, FileOrFunc))
        ret = origFindNextFileA(hFindFile, lpFindFileData);
    
    return ret;
}

BOOL WINAPI MyFindNextFileW(HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData)
{
    bool ret = origFindNextFileW(hFindFile, lpFindFileData);
    if (!wcscmp(lpFindFileData->cFileName,FileOrFuncW))
        ret = origFindNextFileW(hFindFile, lpFindFileData);
    
    return ret;
}


size_t Labs2HideFile()
{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&(PVOID&)origCreateFileA, MyCreateFileA);
    LONG err = DetourTransactionCommit();
    if (err != NO_ERROR)
    {
        Labs2SendMsg((CHAR*)"ERROR: Detoured failed");
        return 1;
    }

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&(PVOID&)origCreateFileW, MyCreateFileW);
    err = DetourTransactionCommit();
    if (err != NO_ERROR)
    {
        Labs2SendMsg((CHAR*)"ERROR: Detoured failed");
        return 1;
    }

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&(PVOID&)origFindFirstFileW, MyFindFirstFileW);
    err = DetourTransactionCommit();
    if (err != NO_ERROR)
    {
        Labs2SendMsg((CHAR*)"ERROR: Detoured failed");
        return 1;
    }

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&(PVOID&)origFindFirstFileA, MyFindFirstFileA);
    err = DetourTransactionCommit();
    if (err != NO_ERROR)
    {
        Labs2SendMsg((CHAR*)"ERROR: Detoured failed");
        return 1;
    }

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&(PVOID&)origFindNextFileW, MyFindNextFileW);
    err = DetourTransactionCommit();
    if (err != NO_ERROR)
    {
        Labs2SendMsg((CHAR*)"ERROR: Detoured failed");
        return 1;
    }

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&(PVOID&)origFindNextFileA, MyFindNextFileA);
    err = DetourTransactionCommit();
    if (err != NO_ERROR)
    {
        Labs2SendMsg((CHAR*)"ERROR: Detoured failed");
        return 1;
    }

    Labs2SendMsg((CHAR*)"Detoured successfully");
    return 0;
}

size_t Labs2Connect()
{
    BOOL SuccessFlag = FALSE;
    DWORD Mode;

    while (1)
    {
        PipeHandle = CreateFileA(PipeName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

        if (PipeHandle != INVALID_HANDLE_VALUE)
            break;

        if (GetLastError() != ERROR_PIPE_BUSY)
            return 1;

        if (!WaitNamedPipeA(PipeName, 20000))
            return 1;
    }

    Mode = PIPE_READMODE_MESSAGE;
    SuccessFlag = SetNamedPipeHandleState(PipeHandle, &Mode, NULL, NULL);

    if (!SuccessFlag)
        return 1;
    return 0;
}

BOOL Labs2SendMsg(CHAR* msg)
{
    BOOL SuccessFlag = FALSE;
    NumberWriteBytes = (lstrlenA(msg) + 1) * sizeof(CHAR);
    SuccessFlag = WriteFile(PipeHandle, msg, NumberWriteBytes, &NumberWrittenBytes, NULL);
    return SuccessFlag;
}

size_t Labs2StartMessageExchange()
{
    BOOL SuccessFlag = FALSE;

    if (!Labs2SendMsg(StartMessage))
        return 1;

    do
    {
        SuccessFlag = ReadFile(PipeHandle, BufferChar, BUFFER_SIZE * sizeof(CHAR), &NumberReadBytes, NULL);
        if (!SuccessFlag && GetLastError() != ERROR_MORE_DATA)
            break;
    } while (!SuccessFlag);

    if (!SuccessFlag)
        return 1;

    if (!strncmp(BufferChar, "-hide", 5))
        command_flag = command_flags::HIDE;
    else if (!strncmp(BufferChar, "-func", 5))
        command_flag = command_flags::FUNC;

    strcpy_s(FileOrFunc, BufferChar + 6);
    swprintf_s(FileOrFuncW, L"%S", FileOrFunc);

}

BOOLEAN Labs2CreateHookForFunc(CHAR* name_func)
{
    if (origPoint == NULL)
    {
        origPoint = DetourFindFunction(DLL_TO_HOOK, name_func);
        if (origPoint == 0)
        {
            Labs2SendMsg((CHAR*)"ERROR: Find function failed");
            return FALSE;
        }

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)origPoint, Labs2Hook);
        LONG err = DetourTransactionCommit();

        if (err == NO_ERROR)
            Labs2SendMsg((CHAR*)"Detoured successfully");
        else
        {
            Labs2SendMsg((CHAR*)"ERROR: Detoured failed");
            return FALSE;
        }
    }
}

extern "C" VOID Labs2HookCallback()
{
    SYSTEMTIME SysTime;
    GetLocalTime(&SysTime);
    sprintf_s(Date, "Time: %02d:%02d:%02d (%s())", SysTime.wHour, SysTime.wMinute, SysTime.wSecond, FileOrFunc);
    if (!ConnectFlag || strcmp(Date, EtalonDate))
    {
        sprintf_s(EtalonDate, "%s", Date);
        Labs2SendMsg(Date);
        ConnectFlag = TRUE;
    }
}

BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,  // handle to DLL module
    DWORD fdwReason,     // reason for calling function
    LPVOID lpReserved)  // reserved
{
    // Perform actions based on the reason for calling.
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        // Initialize once for each new process.
        // Return FALSE to fail DLL load.
        if (!Labs2Connect())
        {
            Labs2StartMessageExchange();
            Labs2SendMsg((CHAR*)"Procces attach...");
            DisableThreadLibraryCalls(hinstDLL);

            if (command_flag == command_flags::FUNC)
                Labs2CreateHookForFunc(FileOrFunc);
            else
                Labs2HideFile();
        }

        break;

    case DLL_THREAD_ATTACH:
        // Do thread-specific initialization.
        break;

    case DLL_THREAD_DETACH:
        // Do thread-specific cleanup.

        break;

    case DLL_PROCESS_DETACH:
        // Perform any necessary cleanup.
        break;
    }
    return TRUE;  // Successful DLL_PROCESS_ATTACH.
}

