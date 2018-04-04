#include <iostream>
#define _WIN32_WINNT 0x0501
#include <string>
#include <windows.h>
#include <sstream>
#include <psapi.h>
#include <algorithm>
using namespace std;
void usage(const char *szName);
DWORD findProcess(string sName);
void errorAndOut(DWORD dwError, string sSection);
bool checkArch(HANDLE hProcess);

int main(int argc, char **argv)
{
    cout << "Injector" << endl;
    cout << "--------" << endl;
    if(argc != 3) usage(argv[0]);
    HANDLE hDLL = CreateFile(argv[2], 0, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if(hDLL == INVALID_HANDLE_VALUE) errorAndOut(GetLastError(), "CreateFile opening dll");
    CloseHandle(hDLL);

    stringstream pidOrName(argv[1]);

    DWORD dwPID = 0;
    pidOrName >> dwPID;
    if(!dwPID) dwPID = findProcess(argv[1]);
    if(!dwPID) errorAndOut(0, "Process ID invalid or process name not found.");
    cout << "Injecting on " << dwPID << "..." << endl;
    HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, false, dwPID);
    if(hProcess == nullptr) errorAndOut(GetLastError(), "OpenProcess");

    cout << "Process " << dwPID << " opened." << endl;
    if(!checkArch(hProcess)) errorAndOut(0, "Incompatible architecture. Compile the proper version and try again.");
    cout << "Allocating memory..." << endl;
    LPVOID lpRemoteMem = VirtualAllocEx(hProcess, nullptr, 1024, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if(lpRemoteMem == nullptr) errorAndOut(GetLastError(), "VirtualAllocEx");
    cout << "Remote process memory = " << (hex) << lpRemoteMem << (dec) << endl;
    char *szDLLName = new char[1024];
    ZeroMemory(szDLLName, 1024);
    DWORD dwSize = strlen(argv[2]);
    if(dwSize > 1023) strncpy(szDLLName, argv[2], 1023);
    else strcpy(szDLLName, argv[2]);
    if(WriteProcessMemory(hProcess, lpRemoteMem, szDLLName, 1024, nullptr) == 0) errorAndOut(GetLastError(), "WriteProcessMemory");
    LPVOID lpLoadLibrary = (LPVOID) GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
    cout << "LoadLibrary address = " << (hex) << lpLoadLibrary << (dec) << endl;
    if(CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE) lpLoadLibrary, lpRemoteMem, 0, nullptr) == nullptr) errorAndOut(GetLastError(), "CreateRemoteThread");
    cout << "CreateRemoteThread successful." << endl;
    delete szDLLName;
    CloseHandle(hProcess);
    return 0;
}

bool checkArch(HANDLE hProcess)
{
    BOOL bWOW = false;
    IsWow64Process(hProcess, &bWOW);
    #ifdef __x86_64__
    if(bWOW) return false;
    else return true;
    #else
    BOOL bOurWOW = false;
    IsWow64Process(GetCurrentProcess(), &bOurWOW);
    if(bOurWOW == bWOW) return true;
    else return false;
    #endif // __x86_64__
}

void usage(const char *szName)
{
    string sName(szName);
    sName = sName.substr(sName.find_last_of("\\")+1);
    cout << "Injects a dll into the target process." << endl << endl;
    cout << "Usage: " << sName << " [PID or process name] [dll]" << endl << endl;
    exit(1);
}

DWORD findProcess(string sName)
{
    transform(sName.begin(), sName.end(), sName.begin(), ::tolower);
    DWORD *pdwProcess = nullptr;
    DWORD cb = 0;
    DWORD dwOut = 0;
    pdwProcess = new DWORD[65536];
    ZeroMemory(pdwProcess, 65536 * sizeof(DWORD));
    if(EnumProcesses(pdwProcess, 65536*sizeof(DWORD), &cb) != 0)
    {
        for(DWORD i = 0; i < cb/sizeof(DWORD); i++)
        {
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pdwProcess[i]);
            if(hProcess != NULL)
            {
                char *szName = new char[32768];
                ZeroMemory(szName, 32768);
                if(GetModuleFileNameEx(hProcess, nullptr, szName, 32768))
                {
                    string pidName(szName);
                    transform(pidName.begin(), pidName.end(), pidName.begin(), ::tolower);
                    if(pidName.find(sName) != string::npos) dwOut = pdwProcess[i];
                }
                delete szName;
                CloseHandle(hProcess);
            }
            if(dwOut) break;
        }
    }
    else
    {
        delete pdwProcess;
        errorAndOut(GetLastError(), "EnumProcesses");
    }
    delete pdwProcess;
    return dwOut;
}

void errorAndOut(DWORD dwError, string sSection)
{
    if(dwError != 0)
    {
        LPSTR messageBuffer = nullptr;
        size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                                     nullptr, dwError, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, nullptr);
        string message(messageBuffer, size);
        LocalFree(messageBuffer);
        message = message.substr(0,message.size()-2);
        cout << "Error with " << sSection << ": " << message << " (" << dwError << ")" << endl;
    }
    else cout << "Error: " << sSection << endl;
    cout << "Cannot continue." << endl;
    exit(1);
}
