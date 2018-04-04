#define _WIN32_WINNT 0x0501
#include "main.h"
#include <string>
#include <map>
#include <sstream>
using namespace std;
map<string,string> mOld;
void restoreHook(string sFunction, string sDLL);
void hookFunction(string sFunction, string sDLL, char* lpDestination);
BOOL WINAPI ReadFileHook(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);
BOOL WINAPI WriteProcessMemoryHook(HANDLE  hProcess,LPVOID lpBaseAddress,LPCVOID lpBuffer,SIZE_T nSize,SIZE_T *lpNumberOfBytesWritten);
BOOL WINAPI ReadProcessMemoryHook(HANDLE hProcess,LPCVOID lpBaseAddress,LPVOID lpBuffer,SIZE_T nSize,SIZE_T *lpNumberOfBytesRead);
BOOL WINAPI WriteFileHook(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);

extern "C" DLL_EXPORT BOOL APIENTRY DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    switch (fdwReason)
    {
        case DLL_PROCESS_ATTACH:
            hookFunction("ReadFile", "kernel32.dll", (char*) &ReadFileHook);
            hookFunction("ReadProcessMemory", "kernel32.dll", (char*) &ReadProcessMemoryHook);
            hookFunction("WriteProcessMemory", "kernel32.dll", (char*) &WriteProcessMemoryHook);
            hookFunction("WriteFile", "kernel32.dll", (char*) &WriteFileHook);
            // attach to process
            // return FALSE to fail DLL load
            break;
    }
    return TRUE; // succesful
}

void logData(string sData)
{
    if (sData.size() == 0) return;
    HANDLE hFile = CreateFile("C:\\Users\\Alex\\Downloads\\injecthook\\out.txt", GENERIC_WRITE, FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    SetFilePointer(hFile, 0, nullptr, FILE_END);
    DWORD dwWritten = 0;
    WriteFile(hFile, sData.c_str(), sData.size(), &dwWritten, nullptr);
    CloseHandle(hFile);
}

BOOL WINAPI ReadProcessMemoryHook(HANDLE hProcess,LPCVOID lpBaseAddress,LPVOID lpBuffer,SIZE_T nSize,SIZE_T *lpNumberOfBytesRead)
{
    restoreHook("ReadProcessMemory", "kernel32.dll");
    BOOL bReturn = ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
    if(*lpNumberOfBytesRead > 0)
    {
        DWORD dwPID = GetProcessId(hProcess);
        string sData((char*)lpBuffer, *lpNumberOfBytesRead);
        stringstream ssData;
        ssData << "Read buffer from address " << (hex) << (DWORD)lpBaseAddress << (dec) << " of size: " << *lpNumberOfBytesRead << " from PID " << dwPID << endl;
        ssData << "-----------------------------------------------" << endl << sData << endl;
        //logData(ssData.str());
    }
    hookFunction("ReadProcessMemory", "kernel32.dll", (char*) &ReadProcessMemoryHook);
    return bReturn;
}

BOOL WINAPI WriteProcessMemoryHook(HANDLE  hProcess,LPVOID lpBaseAddress,LPCVOID lpBuffer,SIZE_T nSize,SIZE_T *lpNumberOfBytesWritten)
{
    restoreHook("WriteProcessMemory", "kernel32.dll");
    BOOL bReturn = WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
    if(*lpNumberOfBytesWritten > 0)
    {
        DWORD dwPID = GetProcessId(hProcess);
        string sData((char*)lpBuffer, *lpNumberOfBytesWritten);
        stringstream ssData;
        ssData << "Wrote buffer to address " << (hex) << (DWORD)lpBaseAddress << (dec)  << " of size: " << *lpNumberOfBytesWritten << " from PID " << dwPID << endl;
        ssData << "-----------------------------------------------" << endl << sData << endl;
        //logData(ssData.str());
    }
    hookFunction("WriteProcessMemory", "kernel32.dll", (char*) &WriteProcessMemoryHook);
    return bReturn;
}

BOOL WINAPI WriteFileHook(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped)
{
    restoreHook("WriteFile", "kernel32.dll");
    BOOL bReturn = WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
    if(*lpNumberOfBytesWritten > 0)
    {
        string sData((char*)lpBuffer, *lpNumberOfBytesWritten);
        stringstream ssData;
        ssData << "Wrote buffer " << " of size: " << *lpNumberOfBytesWritten << endl;
        ssData << "-----------------------------------------------" << endl << sData << endl;
        logData(ssData.str());
    }
    hookFunction("WriteFile", "kernel32.dll", (char*) &WriteFileHook);
    return bReturn;
}

BOOL WINAPI ReadFileHook(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped)
{
    restoreHook("ReadFile", "kernel32.dll");
    BOOL bReturn = ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
    string sData((char*)lpBuffer, *lpNumberOfBytesRead);
    //logData(sData);
    hookFunction("ReadFile", "kernel32.dll", (char*) &ReadFileHook);
    return bReturn;
}

void restoreHook(string sFunction, string sDLL)
{
    string sOld = mOld[sFunction];
    char *szAdd = (char*)GetProcAddress(LoadLibrary(sDLL.c_str()), sFunction.c_str());
    DWORD dwOld = 0;
    DWORD dwOld1 = 0;
    VirtualProtect(szAdd, 1024, PAGE_EXECUTE_READWRITE, &dwOld);
    memcpy(szAdd, sOld.c_str(), 8);
    VirtualProtect(szAdd, 1024, dwOld, &dwOld1);
}

void hookFunction(string sFunction, string sDLL, char* lpDestination)
{
    char *lpOriginal = (char*) GetProcAddress(LoadLibrary(sDLL.c_str()), sFunction.c_str());
    DWORD dwOld = 0;
    DWORD dwOld1 = 0;
    DWORD dwCalc = lpDestination - lpOriginal -5;
    VirtualProtect(lpOriginal, 1024, PAGE_EXECUTE_READWRITE, &dwOld);
    string sOut((const char*)lpOriginal, 8);
    lpOriginal[0] = 0xe9;
    memcpy(lpOriginal+1, &dwCalc, sizeof(DWORD));
    memset(lpOriginal+5, 0xcc, 3);
    VirtualProtect(lpOriginal, 1024, dwOld, &dwOld1);
    mOld[sFunction] = sOut;
}
