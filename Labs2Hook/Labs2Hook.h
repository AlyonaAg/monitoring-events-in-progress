#pragma once

//Shared stuff
#include <windows.h>
#include <stdio.h>
#include <conio.h>
#include <tchar.h>

#define MAX_FUNC_NAME 1024
#define BUFFER_SIZE 512
#define DLL_TO_HOOK "kernel32.dll"

HANDLE PipeHandle = INVALID_HANDLE_VALUE;
LPCSTR PipeName = "\\\\.\\pipe\\mynamedpipe";
DWORD NumberReadBytes = 0;
DWORD NumberWriteBytes = 0;
DWORD NumberWrittenBytes = 0;
CHAR BufferChar[BUFFER_SIZE] = { 0 };
CHAR FileOrFunc[BUFFER_SIZE] = { 0 };
WCHAR FileOrFuncW[BUFFER_SIZE] = { 0 };
CHAR Date[BUFFER_SIZE] = { 0 };
CHAR EtalonDate[BUFFER_SIZE] = { 0 };
CHAR StartMessage[] = "Start";
BOOLEAN ConnectFlag = FALSE;

extern "C" LPVOID origPoint = NULL;
extern "C" void Labs2Hook();
BOOL Labs2SendMsg(CHAR* msg);

enum class command_flags { HIDE, FUNC, UNKNOW };

command_flags command_flag = command_flags::UNKNOW;

HANDLE (WINAPI* origCreateFileA) (LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) = CreateFileA;
HANDLE (WINAPI* origCreateFileW) (LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) = CreateFileW;
HANDLE (WINAPI* origFindFirstFileW) (LPCWSTR lpFileName, LPWIN32_FIND_DATA lpFindFileData) = FindFirstFileW;
HANDLE (WINAPI* origFindFirstFileA)(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData) = FindFirstFileA;
BOOL (WINAPI* origFindNextFileW) (HANDLE hFindFile, LPWIN32_FIND_DATA lpFindFileData) = FindNextFileW;
BOOL (WINAPI* origFindNextFileA) (HANDLE hFindFile, LPWIN32_FIND_DATAA  lpFindFileData) = FindNextFileA;