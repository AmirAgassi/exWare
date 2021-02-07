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

    int retcheckInstructions[] = { 0x72, 0xA1, 0x8B };
    int replacementByte = 0xEB;

    void patchRetcheck(BYTE* functionalAddr) {
        if (functionalAddr[0] == 0x72 && functionalAddr[2] == 0xA1 && functionalAddr[7] == 0x8B) {
            WriteProcessMemory(GetCurrentProcess(), *(LPVOID*)&functionalAddr, (LPVOID)&replacementByte, 1, NULL);
        }
    }

    void restoreRetcheck(BYTE* functionalAddr) {
        if (functionalAddr[0] == replacementByte && functionalAddr[2] == 0xA1 && functionalAddr[7] == 0x8B) {
            WriteProcessMemory(GetCurrentProcess(), *(LPVOID*)&functionalAddr, (LPVOID)&retcheckInstructions[0], 1, NULL);
        }
    }

    bool checkRetcheck(DWORD addy) {
        BYTE* functionalAddr = (BYTE*)addy;
        while (!(functionalAddr[0] == retcheckInstructions[0] && functionalAddr[2] == retcheckInstructions[1] && functionalAddr[7] == retcheckInstructions[2])) {
            if (functionalAddr[0] == replacementByte && functionalAddr[2] == 0xA1 && functionalAddr[7] == 0x8B) {
                restoreRetcheck(functionalAddr);
                return false;
            }
            functionalAddr += 1;
        }
        patchRetcheck(functionalAddr);
        return true;
    }
}

void printTop(int state) {
    cout << "lua_state stack top: " << pseudogettop(state) << endl;
}


namespace AOB {
    bool Check(const BYTE* pd, const BYTE* aob, const char* mask)
    {
        for (; *mask; ++mask, ++pd, ++aob)
            if (*mask != '?' && *pd != *aob)
                return false;

        return (*mask) == NULL;
    }

    DWORD FindPattern(const char* aob, const char* mask)
    {
        for (DWORD ind = (DWORD)GetModuleHandle(0); ind <= 0xFFFFFFF; ++ind) {
            if (Check((BYTE*)ind, (BYTE*)aob, mask))
                return ind;
        }
        return 0x00000000;
    }
}


namespace address {
    int getfield_s = aslr(0x1360240); 
    int pushstring_s = AOB::FindPattern("\x55\x8B\xEC\x51\x8B\xC2\x89\x45\xFC\x53\x8B\xD9\x85\xC0\x75\x08", "xxxxxxxxxxxxxxxx"); //0x01360DE0
    //int pushvalue_s = aslr(0x01360F50);   uses a pseudo function
    int pcall_s = AOB::FindPattern("\x55\x8B\xEC\x8B\x55\x14\x83\xEC\x08\x53\x57\x8B\x7D\x08\x85\xD2", "xxxxxxxxxxxxxxxx"); //0x013609B0
}
namespace clua {
    typedef int(__stdcall* clua_getfield)(int, int, const char*);
    clua_getfield getfield = (clua_getfield)address::getfield_s;
    typedef int(__fastcall* clua_pushstring)(int, int, const char*);
    clua_pushstring pushstring = (clua_pushstring)address::pushstring_s; 
    //typedef void* (__stdcall* clua_pushvalue)(int, int);
    //clua_pushvalue pushvalue = (clua_pushvalue)address::pushvalue_s;
    typedef void*(__cdecl* clua_pcall)(int, int, int, int);
    clua_pcall pcall = (clua_pcall)address::pcall_s;
   
    

}

void getfield(int a1, int a2, const char* a3) {
    retcheck::checkRetcheck(address::getfield_s);
    clua::getfield(a1, a2, a3);
    retcheck::checkRetcheck(address::getfield_s);
}


void pcall(int a1, int a2, int a3, int a4) {
    retcheck::checkRetcheck(address::pcall_s);
    clua::pcall(a1, a2, a3, a4);
    retcheck::checkRetcheck(address::pcall_s);
}




#define LUA_REGISTRYINDEX       (-10000)
#define LUA_ENVIRONINDEX        (-10001)
#define LUA_GLOBALSINDEX        (-10002)
DWORD* index2adr(DWORD* lua_state, signed int index) {
    // IDA PRO @ sub_1360F50

    _DWORD* result; // eax
    int v3; // esi
    int v4; // edx
    int v5; // ecx

    if (index > LUA_REGISTRYINDEX)
        return (_DWORD*)(lua_state[6] + 16 * index);

    switch (index)
    {
        case LUA_GLOBALSINDEX:
            return lua_state + 20;

        case LUA_ENVIRONINDEX:
            v4 = lua_state[7];
            result = lua_state + 14;
            if (v4 == lua_state[11])
                v5 = lua_state[20];
            else
                v5 = *(_DWORD*)(**(_DWORD**)(v4 + 12) + 16);
            *result = v5;
            result[3] = 8;
            break;

        case LUA_REGISTRYINDEX:
            result = (_DWORD*)(((unsigned int)(lua_state + 4) ^ lua_state[4]) + 368);
            break;

        default:
            v3 = **(_DWORD**)(lua_state[7] + 12);
            if (-10002 - index > *(unsigned __int8*)(v3 + 7))
                result = NULL;  //&unk_2153A30;
            else
                result = (_DWORD*)(v3 + 16 * (-10002 - index) + 24);
            break;

    }
    return result;

}

void pseudopushvalue(int a1, int a2) {
    DWORD* v4 = index2adr((_DWORD*)a1, a2);
    DWORD* v3;
    DWORD* v2;
    v3 = *(DWORD**)(a1 + 24);
    *v3 = *(DWORD*)v4;
    *(_DWORD*)(a1 + 24) += 16;
}


void main() {

    Console("exWare Executor");

    cout << "exWare Early Development Build" << endl << endl << endl;

    int scriptc = aslr(0x01F88AC8);
    int state;
    DWORD scriptContext;

    cout << "Scanning for ScriptContext... ";
    scriptContext = memory::Scan((char*)&scriptc);
    cout << "Done" << endl << "Scanning for lua_state... ";

    state = getstate((DWORD)scriptContext);
    if (pseudogettop(state) == 0) {
        cout << "Done." << endl;
    }
    else {
        cout << "Failed." << endl << "FATAL: ScriptContext failed to initialize, lua_state is nonexistant. The exploit will not continue. " << endl << "Top: " << pseudogettop(state) << " (should be 0)";
        return;
    }
   

    getfield(state, -10002, "workspace");
    getfield(state, -1, "breakJoints");
    pseudopushvalue(state, -2);
    pcall(state, 1, 0, 0);
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

