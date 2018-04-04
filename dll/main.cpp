#include "main.h"
#include <string>
#include <vector>
using namespace std;
vector<string> vOlds;
void restoreHook(string sFunction, string sDLL, string sOld);
string hookFunction(string sFunction, string sDLL, char* lpDestination);
BOOL WINAPI ReadFileHook(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);

extern "C" DLL_EXPORT BOOL APIENTRY DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    switch (fdwReason)
    {
        case DLL_PROCESS_ATTACH:
            string sOut = hookFunction("ReadFile", "kernel32.dll", (char*) &ReadFileHook);
            vOlds.push_back(sOut);
            // attach to process
            // return FALSE to fail DLL load
            break;
    }
    return TRUE; // succesful
}

void logData(string sData)
{
    string sSep = "----------------------------------------------\n";
    HANDLE hFile = CreateFile("C:\\Users\\Alex\\Downloads\\injecthook\\out.txt", GENERIC_WRITE, FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    SetFilePointer(hFile, 0, nullptr, FILE_END);
    DWORD dwWritten = 0;
    WriteFile(hFile, sData.c_str(), sData.size(), &dwWritten, nullptr);
    WriteFile(hFile, sSep.c_str(), sSep.size(), &dwWritten, nullptr);
    CloseHandle(hFile);
}

BOOL WINAPI ReadFileHook(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped)
{
    restoreHook("ReadFile", "kernel32.dll", vOlds[0]);
    BOOL bReturn = ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
    string sData((char*)lpBuffer, *lpNumberOfBytesRead);
    logData(sData);
    string sOut = hookFunction("ReadFile", "kernel32.dll", (char*) &ReadFileHook);
    return bReturn;
}

void restoreHook(string sFunction, string sDLL, string sOld)
{
    char *szAdd = (char*)GetProcAddress(LoadLibrary(sDLL.c_str()), sFunction.c_str());
    DWORD dwOld = 0;
    DWORD dwOld1 = 0;
    VirtualProtect(szAdd, 1024, PAGE_EXECUTE_READWRITE, &dwOld);
    memcpy(szAdd, sOld.c_str(), 8);
    VirtualProtect(szAdd, 1024, dwOld, &dwOld1);
}

string hookFunction(string sFunction, string sDLL, char* lpDestination)
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
    return sOut;
}
