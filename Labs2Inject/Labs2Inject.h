#pragma once
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <debugapi.h>
#include <strsafe.h>
#include <string>

#define MAX_PRINT_TEXT_LENGTH 1024
#define BUFFER_SIZE 512
#define LABS2_PRINT(a, ...) printf("[LABS2 INJECT] " a, ##__VA_ARGS__); fflush(stdout);
#define LABS2_PRINT_HOOK(a, ...) printf("[LABS2 HOOK] " a, ##__VA_ARGS__); fflush(stdout);


enum class command_flags { HIDE, FUNC, UNKNOW};
enum class process_flags { PID, NAME, UNKNOW};

command_flags command_flag = command_flags::UNKNOW;
process_flags process_flag = process_flags::UNKNOW;

std::string StringToSend;

LPCTSTR PipeName = TEXT("\\\\.\\pipe\\mynamedpipe");
HANDLE PipeHandle = INVALID_HANDLE_VALUE;
HANDLE remote_tread_h;
TCHAR full_dll_path[MAX_PATH];

HANDLE Labs2_InjectDLLIntoProcess(DWORD procID, LPCWSTR dllName);