#pragma once

#include "pch.h"
#include <iostream>
#include <string>
#include <sstream>
#include <string>
#include <vector>
#include <algorithm>
#include <functional>
#include <iterator>
#include <string.h>
using namespace std;
#define _CRT_SECURE_NO_DEPRICATE
#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#define _DWORD DWORD


namespace memory
{
    bool Compare(const char* pData, const char* bMask, const char* szMask)
    {
        while (*szMask) {
            if (*szMask != '?') {
                if (*pData != *bMask) return 0;
            }
            ++szMask, ++pData, ++bMask;
        }
        return 1;
    }
    DWORD Scan(const char* vftable)
    {
        MEMORY_BASIC_INFORMATION MBI = { 0 };
        SYSTEM_INFO SI = { 0 };
        GetSystemInfo(&SI);
        DWORD Start = (DWORD)SI.lpMinimumApplicationAddress;
        DWORD End = (DWORD)SI.lpMaximumApplicationAddress;
        do
        {
            while (VirtualQuery((void*)Start, &MBI, sizeof(MBI))) {
                if ((MBI.Protect & PAGE_READWRITE) && !(MBI.Protect & PAGE_GUARD))
                {
                    for (DWORD i = (DWORD)(MBI.BaseAddress); i - (DWORD)(MBI.BaseAddress) < MBI.RegionSize; ++i)
                    {
                        if (Compare((const char*)i, vftable, "xxxx"))
                            return i;
                    }
                }
                Start += MBI.RegionSize;
            }
        } while (Start < End);
        return 0;
    }
}


#define aslr(x)(x - 0x400000 + (DWORD)GetModuleHandleA(0))




void Console(const char* N) {

    AllocConsole();
    SetConsoleTitleA(N);
    freopen("CONOUT$", "w", stdout);
    freopen("CONIN$", "r", stdin);

    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, 12);


}


int getstate(DWORD ScriptContext) {
    return *(DWORD*)(ScriptContext + 180) ^ (ScriptContext + 180);
}

int pseudogettop(int state) {
    return (*(DWORD*)(state + 24) - *(DWORD*)(state + 20)) >> 4;
}



string int2hex(int addr) {
    std::stringstream stream;
    stream << std::hex << std::uppercase << addr;
    std::string result(stream.str());
    return result;
}

namespace retcheck {

    void patchRetcheck(BYTE* functionalAddr, DWORD addr) {
        int replacementByte = 0xEB;

        string result = int2hex((int)functionalAddr);
        DWORD jmpLoc = functionalAddr - (BYTE*)addr;
        addr += jmpLoc;
        if (functionalAddr[0] == 0x72 && functionalAddr[2] == 0xA1 && functionalAddr[7] == 0x8B) {
            //cout << "Found retcheck at 0x" << uppercase << result << ". (0x" << int2hex(*(BYTE*)addr) << ", 0xA1, 0x8B)" << endl;
            //cout << "Writing 0xEB to 0x" << int2hex(addr) << endl;
            WriteProcessMemory(GetCurrentProcess(), *(LPVOID*)&addr, (LPVOID)&replacementByte, 1, NULL);
        }
    }

    void restoreRetcheck(BYTE* functionalAddr, DWORD addr) {

        int retcheckInstructions[] = { 0x72, 0xA1, 0x8B };
        int replacementByte = 0xEB;
        string result = int2hex((int)functionalAddr);
        DWORD jmpLoc = functionalAddr - (BYTE*)addr;
        addr += jmpLoc;

        if (functionalAddr[0] == replacementByte && functionalAddr[2] == 0xA1 && functionalAddr[7] == 0x8B) {
            //cout << "Found BYPASSED retcheck at 0x" << uppercase << result << ". (0x" << int2hex(functionalAddr[0]) << ", 0xA1, 0x8B)" << endl;
            //cout << "Unpatching 0xEB back to 0x" << int2hex(retcheckInstructions[0]) << endl;
            WriteProcessMemory(GetCurrentProcess(), *(LPVOID*)&addr, (LPVOID)&retcheckInstructions[0], 1, NULL);
        }
    }

    bool checkRetcheck(DWORD addr) {
        int retcheckInstructions[] = { 0x72, 0xA1, 0x8B };
        int replacementByte = 0xEB;

        BYTE* functionalAddr = (BYTE*)addr;
        while (!(functionalAddr[0] == retcheckInstructions[0] && functionalAddr[2] == retcheckInstructions[1] && functionalAddr[7] == retcheckInstructions[2])) {
            if (functionalAddr[0] == replacementByte && functionalAddr[2] == 0xA1 && functionalAddr[7] == 0x8B) {
                restoreRetcheck(functionalAddr, addr);
                return false;
            }
            functionalAddr += 1; // All calls are aligned to 16 bytes!! 1 spams too much
        }
        patchRetcheck(functionalAddr, addr);
        return true;
    }
}

void printTop(int state) {
    cout << "lua_state stack top: " << pseudogettop(state) << endl;
}




namespace address {
    int getfield_s = aslr(0x1360240);
    int pushstring_s = aslr(0x01360DE0);
}
namespace clua {
    typedef int(__stdcall* clua_getfield)(int, int, const char*);
    clua_getfield getfield = (clua_getfield)address::getfield_s; //works
    typedef int(__fastcall* clua_pushstring)(int, int, const char*);
    clua_pushstring getfield = (clua_pushstring)address::pushstring_s; //works

}

void getfield(int a1, int a2, const char* a3) {
    retcheck::checkRetcheck(aslr(0x1360240));
    clua::getfield(a1, a2, a3);
    retcheck::checkRetcheck(aslr(0x1360240));

}
void main() {

    Console("exWare Executor");

    cout << "exWare Early Development Build" << endl << endl << endl;

    int scriptc = aslr(0x01F88AC8);
    cout << "Scanning for ScriptContext... ";
    DWORD scriptContext = memory::Scan((char*)&scriptc);
    cout << "Done" << endl << "Scanning for lua_state... ";

    int state = getstate((DWORD)scriptContext);
    if (pseudogettop(state) == 0) {
        cout << "Done." << endl;
    }
    else {
        cout << "Failed." << endl << "FATAL: ScriptContext failed to initialize, lua_state is nonexistant. The exploit will not continue. " << endl << "Top: " << pseudogettop(state) << " (should be 0)";
        return;
    }

    printTop(state);
    getfield(state, -10002, "game");
    getfield(state, -1, "Workspace");
    getfield(state, -1, "runtoheven");
    printTop(state);
}




BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        main();
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

