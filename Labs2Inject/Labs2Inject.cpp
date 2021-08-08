#include "Labs2Inject.h"


void Labs2GetAnswerToRequest(LPTSTR Request, LPTSTR Reply, LPDWORD NumberBytes)
{
    LABS2_PRINT_HOOK("%s\n", (CHAR*)Request);

    if (FAILED(StringCchCopy(Reply, BUFFER_SIZE, TEXT("Default answer from server"))))
    {
        *NumberBytes = 0;
        Reply[0] = 0;
        LABS2_PRINT("ERROR: StringSshCopy error\n");
        return;
    }
    *NumberBytes = (lstrlen(Reply) + 1) * sizeof(TCHAR);
}

void Labs2InstanceThread(HANDLE HandlePipe)
{
    HANDLE HeapHandle = GetProcessHeap();
    CHAR* Request = (CHAR*)HeapAlloc(HeapHandle, 0, BUFFER_SIZE * sizeof(CHAR));
    CHAR* Reply = (CHAR*)HeapAlloc(HeapHandle, 0, BUFFER_SIZE * sizeof(CHAR));
    DWORD NumberReadBytes = 0;
    DWORD NumberRypliedBytes = 0;
    DWORD NumberWrittenBytes = 0;
    BOOL  SuccessFlag = FALSE;
    LPCSTR DataToSend;

    if (Request == NULL)
    {
        LABS2_PRINT("ERROR: InstanceThread got an unexpected NULL heap allocation.\n");
        if (Reply != NULL)
            HeapFree(HeapHandle, 0, Reply);
        return;
    }

    if (Reply == NULL)
    {
        LABS2_PRINT("ERROR: InstanceThread got an unexpected NULL heap allocation.\n");

        if (Request != NULL)
            HeapFree(HeapHandle, 0, Request);
        return;
    }

    while (1)
    {
        SuccessFlag = ReadFile(HandlePipe, Request, BUFFER_SIZE * sizeof(CHAR), &NumberReadBytes, NULL);

        if (!SuccessFlag || NumberReadBytes == 0)
        {
            if (GetLastError() == ERROR_BROKEN_PIPE)
            {
                LABS2_PRINT("Client disconnected.\n");
            }
            else
            {
                LABS2_PRINT("ERROR: ReadFile error.\n");
            }
            
            break;
        }

        Labs2GetAnswerToRequest((TCHAR*)Request, (TCHAR*)Reply, &NumberRypliedBytes);

        if (!strcmp(Request, "Start"))
        {
            DataToSend = StringToSend.c_str();
            SuccessFlag = WriteFile(HandlePipe, DataToSend, NumberRypliedBytes, &NumberWrittenBytes, NULL);

            if (!SuccessFlag || NumberRypliedBytes != NumberWrittenBytes)
            {
                LABS2_PRINT("ERROR: WriteFile error\n");
                break;
            }
        }

        //if (command_flag == command_flags::HIDE)
        //   break;
    }

    FlushFileBuffers(HandlePipe);
    DisconnectNamedPipe(HandlePipe);
    CloseHandle(HandlePipe);

    HeapFree(HeapHandle, 0, Request);
    HeapFree(HeapHandle, 0, Reply);

    return;
}

size_t Labs2CreateServer(DWORD pid)
{
    LABS2_PRINT("Start creating pipe...\n");

    BOOL   ConnectFlag = FALSE;
    DWORD  ThreadID = 0;
    HANDLE ThreadHandle = NULL;

    PipeHandle = CreateNamedPipe(PipeName, PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, PIPE_UNLIMITED_INSTANCES, BUFFER_SIZE, BUFFER_SIZE, 0, NULL);

    if (PipeHandle == INVALID_HANDLE_VALUE || PipeHandle == NULL)
    {
        LABS2_PRINT("ERROR: CreateNamedPipe.\n");
        return 1;
    }
    LABS2_PRINT("Pipe created.\n");

    remote_tread_h = Labs2_InjectDLLIntoProcess(pid, full_dll_path);
    if (remote_tread_h == NULL)
    {
        LABS2_PRINT("ERROR: Unable to inject DLL to process.\n");
        system("pause");
        return __LINE__;
    }
    LABS2_PRINT("Injection to process success!\n");

    ConnectFlag = ConnectNamedPipe(PipeHandle, NULL) ?
        TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);

    if (ConnectFlag)
    {
        LABS2_PRINT("Client connected!\n");
        Labs2InstanceThread(PipeHandle);
    }
    else
    {
        LABS2_PRINT("Client no connected.\n");
        CloseHandle(PipeHandle);
    }

    return 0;
}


BOOL Labs2SetPrivilege(HANDLE hToken, LPCTSTR szPrivName, BOOL fEnable) {
    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    LookupPrivilegeValue(NULL, szPrivName, &tp.Privileges[0].Luid);
    tp.Privileges[0].Attributes = fEnable ? SE_PRIVILEGE_ENABLED : 0;
    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    return((GetLastError() == ERROR_SUCCESS));
}

DWORD Labs2GetProcessID(LPCTSTR targetName)
{
    HANDLE snapHandle = NULL;
    PROCESSENTRY32 processEntry = { 0 };

    if ((snapHandle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)) == INVALID_HANDLE_VALUE) 
        return 0;

    processEntry.dwSize = sizeof(PROCESSENTRY32);
    Process32First(snapHandle, &processEntry);

    do {
        if (wcscmp(processEntry.szExeFile, targetName) == 0) 
            return processEntry.th32ProcessID;
    } while (Process32Next(snapHandle, &processEntry));

    if (snapHandle != INVALID_HANDLE_VALUE) 
        CloseHandle(snapHandle);
    
    return 0;
}

HANDLE Labs2_InjectDLLIntoProcess(DWORD procID, LPCWSTR dllName)
{
    HANDLE hToken = NULL, hCurrentProc = GetCurrentProcess(), hProcess = NULL, hThread = NULL;
    LPVOID dll_name = 0, load_library_p = NULL;
    DWORD ThreadID = 0;
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procID);

    if (!OpenProcessToken(hCurrentProc, TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken)) 
    {
        LABS2_PRINT("ERROR: OpenProcessToken 0x%x", GetLastError());
        goto COMPLETE;
    }
         
    dll_name = VirtualAllocEx(hProcess, NULL, MAX_PATH * sizeof(TCHAR), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

    if (dll_name == 0)
    {
        LABS2_PRINT("ERROR: VirtualAllocEx 0x%x\n", GetLastError());
        goto COMPLETE;
    }

    if (WriteProcessMemory(hProcess, dll_name, dllName, (lstrlen(dllName)+1)*sizeof(TCHAR), NULL) == 0) 
    {
        LABS2_PRINT("ERROR: WriteProcessMemory 0x%x\n", GetLastError());
        goto COMPLETE;
    }

#ifdef UNICODE
    load_library_p = GetProcAddress(LoadLibraryA("kernel32.dll"), "LoadLibraryW");
#else
    load_library_p = GetProcAddress(LoadLibrary(TEXT("kernel32.dll")), "LoadLibraryA");
#endif

    hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)load_library_p, dll_name, 0, &ThreadID);
    if (hThread == NULL) 
    {
        LABS2_PRINT("ERROR: creating thread 0x%x\n", GetLastError());
        goto COMPLETE;
    }

COMPLETE:
    if (hToken != NULL)
        CloseHandle(hToken);
    if (hProcess != NULL)
        CloseHandle(hProcess);

    return hThread;
}

void usage()
{
    LABS2_PRINT("ERROR: invalid input parameters\n");
}

int main(int argc, char* argv[])
{
    LPCTSTR dll_name = TEXT("Labs2Hook.dll");
    TCHAR proc_name_t[100];
    DWORD pid = 0;

    if (argc < 5)
    {
        usage();
        system("pause");
        return __LINE__;
    }

    if (!strcmp(argv[1], "-pid"))
        process_flag = process_flags::PID;
    else if (!strcmp(argv[1], "-name"))
        process_flag = process_flags::NAME;


    if (!strcmp(argv[3], "-func"))
        command_flag = command_flags::FUNC;
    else if (!strcmp(argv[3], "-hide"))
        command_flag = command_flags::HIDE;

    if (command_flag == command_flags::UNKNOW || process_flag == process_flags::UNKNOW)
    {
        LABS2_PRINT("ERROR: invalid input parameters\n");
        system("pause");
        return __LINE__;
    }

    memset(full_dll_path, 0, sizeof(full_dll_path));
    if (GetFullPathName(dll_name, sizeof(full_dll_path) / sizeof(TCHAR), full_dll_path, NULL) == 0)
    {
        LABS2_PRINT("ERROR: Unable to get full path of %S.\n", dll_name);
        system("pause");
        return __LINE__;
    }

    if (process_flag == process_flags::NAME)
    {
        swprintf_s(proc_name_t, L"%S", argv[2]);
        pid = Labs2GetProcessID(proc_name_t);
        if (pid == 0)
        {
            LABS2_PRINT("ERROR: Unable to find process %S.\n", proc_name_t);
            system("pause");
            return __LINE__;
        }
    }
    else
        pid = atoi(argv[2]);

    StringToSend.append(argv[3]).append(" ").append(argv[4]);

	LABS2_PRINT("Starting...\n");
    //WaitForSingleObject(remote_tread_h, -1);
    Labs2CreateServer(pid);
    LABS2_PRINT("COMPLETED!\n");

    return 0;
}