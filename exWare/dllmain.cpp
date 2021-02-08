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
#include <assert.h>
using namespace std;
#define _CRT_SECURE_NO_DEPRICATE
#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#define _DWORD DWORD

// Louka's old (modified) memory namespace. Thank you
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
        return 69;
    }

}




namespace address {
    int getfield_s = AOB::FindPattern("\x55\x8B\xEC\x8B\x55\x0C\x83\xEC\x10\x56\x8B\x75\x08\x57\x85\xD2", "xxxxxxxxxxxxxxx"); // 0x1360240
    int pushstring_s = AOB::FindPattern("\x55\x8B\xEC\x51\x8B\xC2\x89\x45\xFC\x53\x8B\xD9\x85\xC0\x75\x08", "xxxxxxxxxxxxxxxx"); //0x01360DE0
    int pcall_s = AOB::FindPattern("\x55\x8B\xEC\x8B\x55\x14\x83\xEC\x08\x53\x57\x8B\x7D\x08\x85\xD2", "xxxxxxxxxxxxxxxx"); //0x013609B0
    int gettable_s = aslr(0x13603A0);
    int remove_s = aslr(0x01361470);
    int equal_s = aslr(0x013610A0);
    int settable_s = aslr(0x1361970);
    int isnumber_s = aslr(0x13605E0);
    int replace_s = aslr(0x1361500);
    int getmetafield_s = aslr(0x1362720);
    int call_s = aslr(0x135FD70);
    int setfield_s = aslr(0x013616D0);
    int pushcclosure_s = aslr(0x01360AC0);
    int pushinteger_s = aslr(0x01360C00);
    int gc_s = aslr(0x1360080);
}
namespace clua {
    typedef int(__stdcall* clua_getfield)(int, int, const char*);
    clua_getfield getfield = (clua_getfield)address::getfield_s;

    typedef int(__fastcall* clua_pushstring)(int, const char*);
    clua_pushstring pushstring = (clua_pushstring)address::pushstring_s; 

    typedef void* (__cdecl* clua_pcall)(int, int, int, int);
    clua_pcall pcall = (clua_pcall)address::pcall_s;

    typedef void* (__cdecl* clua_gettable)(int, int);
    clua_gettable gettable = (clua_gettable)address::gettable_s;

    typedef void* (__cdecl* clua_remove)(int, int);
    clua_remove remove = (clua_remove)address::remove_s;

    typedef int(__cdecl* clua_equal)(int, int, int);
    clua_equal equal = (clua_equal)address::equal_s;

    typedef int(__cdecl* clua_settable)(int, int);
    clua_settable settable = (clua_settable)address::settable_s;

    typedef int(__cdecl* clua_isnumber)(int, signed int);
    clua_isnumber isnumber = (clua_isnumber)address::isnumber_s;

    typedef int(__cdecl* clua_replace)(int, signed int);
    clua_replace replace = (clua_replace)address::replace_s;

    typedef int(__cdecl* clua_getmetafield)(int, int, const char*);
    clua_getmetafield getmetafield = (clua_getmetafield)address::getmetafield_s;

    typedef int(__cdecl* clua_call)(int, int, int);
    clua_call call = (clua_call)address::call_s;

    typedef int* (__stdcall* clua_setfield)(int, signed int, const char*);
    clua_setfield setfield = (clua_setfield)address::setfield_s;

    typedef int* (__stdcall* clua_pushcclosure)(int, int, int, int, int);
    clua_pushcclosure pushcclosure = (clua_pushcclosure)address::pushcclosure_s;

    typedef int (__cdecl* clua_gc)(int, int, int);
    clua_gc gc = (clua_gc)address::gc_s;


}

void getfield(int a1, int a2, const char* a3) {
    retcheck::checkRetcheck(address::getfield_s);
    clua::getfield(a1, a2, a3);
    retcheck::checkRetcheck(address::getfield_s);
}

void gc(int a1, int a2, int a3) {
    retcheck::checkRetcheck(address::getfield_s);hinteger_s);
    clua::pushinteger(a1, a2);
    retcheck::checkRetcheck(address::pushinteger_s);
}

void pushcclosure(int a1, int a2, int a3, int a4, int a5) {
    retcheck::checkRetcheck(address::pushcclosure_s);
    clua::pushcclosure(a1, a2, a3, a4, a5);
    retcheck::checkRetcheck(address::pushcclosure_s);
}

void call(int a1, int a2, int a3) {
    retcheck::checkRetcheck(address::call_s);
    clua::call(a1, a2, a3);
    retcheck::checkRetcheck(address::call_s);
}

void setfield(int a1, int a2, const char* a3) {
    retcheck::checkRetcheck(address::setfield_s);
    clua::setfield(a1, a2, a3);
    retcheck::checkRetcheck(address::setfield_s);
}

void pushstring(int a1, const char* a2) {
    retcheck::checkRetcheck(address::pushstring_s);
    clua::pushstring(a1, a2);
    retcheck::checkRetcheck(address::pushstring_s);
}
void pcall(int a1, int a2, int a3, int a4) {
    retcheck::checkRetcheck(address::pcall_s);
    clua::pcall(a1, a2, a3, a4);
    retcheck::checkRetcheck(address::pcall_s);
}
void gettable(int a1, int a2) {
    retcheck::checkRetcheck(address::gettable_s);
    clua::gettable(a1, a2);
    retcheck::checkRetcheck(address::gettable_s);
}

void remove(int a1, int a2) {
    retcheck::checkRetcheck(address::remove_s);
    clua::remove(a1, a2);
    retcheck::checkRetcheck(address::remove_s);
}

void settable(int a1, int a2) {
    retcheck::checkRetcheck(address::settable_s);
    clua::settable(a1, a2);
    retcheck::checkRetcheck(address::settable_s);
}

void replace(int a1, int a2) {
    retcheck::checkRetcheck(address::replace_s);
    clua::replace(a1, a2);
    retcheck::checkRetcheck(address::replace_s);
}

int equal(int a1, int a2, int a3) {
    return clua::equal(a1, a2, a3);
}
#define LUA_REGISTRYINDEX       (-10000)
#define LUA_ENVIRONINDEX        (-10001)
#define LUA_GLOBALSINDEX        (-10002)


DWORD* index2adr(DWORD* lua_state, signed int index) {
    // IDA PRO @ sub_1360F50
    _DWORD* result; // eax
    int v3;         // esi
    int v4;         // edx
    int v5;         // ecx
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

void pushvalue(int a1, int a2) {
    DWORD* v4 = index2adr((_DWORD*)a1, a2);
    DWORD* v3 = *(DWORD**)(a1 + 24);
    *v3 = *(DWORD*)v4;
    *(_DWORD*)(a1 + 24) += 16;
}

void pushboolean(int a1, int a2) {
    DWORD* v2 = *(_DWORD**)(a1 + 24);
    *v2 = a2 != 0;
    v2[3] = 1;
    *(_DWORD*)(a1 + 24) += 16;
}

int pcallx(int a1, int a2, int a3) {
    pcall(a1, a2, a3, 0);
    return 1;
}

void settop(int a1, int a2) {
    int v2; // ecx
    int i; // esi
    int v4; // eax
    int* result; // eax

    v2 = 16 * a2;
    if (a2 < 0)
    {
        v4 = v2 + *(_DWORD*)(a1 + 24) + 16;
    }
    else
    {
        for (i = *(_DWORD*)(a1 + 20); *(_DWORD*)(a1 + 24) < (unsigned int)(i + v2); i = *(_DWORD*)(a1 + 20))
        {
            *(_DWORD*)(*(_DWORD*)(a1 + 24) + 12) = 0;
            *(_DWORD*)(a1 + 24) += 16;
        }
        v4 = v2 + i;
    }
    *(_DWORD*)(a1 + 24) = v4;

}


BOOL toboolean(int a1x, signed int a2) {
    DWORD* a1 = (DWORD*)a1x;
    _DWORD* v2; // edx
    BOOL result; // eax
    _DWORD* v4; // edx

    if (a2 <= 0)
    {
        v4 = index2adr(a1, a2);
        result = (v4[3] & (*v4 | 0xFFFFFFFE)) != 0;
    }
    else
    {
        cout << "FATAL: POSITIVE TOBOOLEAN INDEX QUERIED. ill fix this if its ever an actual error, fuck is 0x2153A30 supposed to be??" << endl;
        /*v2 = &unk_2153A30;
        if ((unsigned int)(16 * a2 - 16 + a1[5]) < a1[6])
            v2 = (_DWORD*)(16 * a2 - 16 + a1[5]);
        result = (v2[3] & (*v2 | 0xFFFFFFFE)) != 0;*/
    }
    return result;

}

int* insert(int a1x, signed int a2) {
    DWORD* a1 = (DWORD*)a1x;
    DWORD* v2; // ecx
    DWORD* v3; // edx
    _DWORD* v4; // eax
    int* result; // eax
    if (a2 <= 0)
    {
        v4 = index2adr(a1, a2);
        v2 = (DWORD*)a1[6];
        v3 = v4;
    }
    else
    {
        v2 = (DWORD*)a1[6];
        v3 = (DWORD*)(a1[5] + 16 * a2 - 16);
        if (v2 > v3)
        {
            do
            {
            LABEL_6:
                *v2 = *(v2 - 1);
                --v2;
            } while (v2 > v3);
            v2 = (DWORD*)a1[6];
            goto LABEL_8;
        }
        int v = aslr(0x2153A30);
        DWORD x = (DWORD)v;
        v3 = &x;
    }
    if (v2 > v3)
        goto LABEL_6;
LABEL_8:
    *v3 = *v2;
    return 0;
}



void pushnumber(int a1x, __int64 a2) {
    DWORD* a1 = (DWORD*)a1x;
    int v2; // eax
    int* result; // eax

    v2 = a1[6];
    *(DWORD*)v2 = aslr(0x28D9D90) ^ a2;
    *(_DWORD*)(v2 + 12) = 4;
    a1[6] += 16;

}



double tonumber(int a1x, signed int a2) {
    DWORD* a3 = 0;
    DWORD* a1 = (DWORD*)a1x;
    _DWORD* v3; // edx
    double result; // st7
    char v5; // [esp+0h] [ebp-10h]
    result = 0;
    if (a2 <= 0)
    {
        v3 = index2adr(a1, a2);
    }
    else
    {
        /*
        v3 = &unk_2153A30;
        if ((unsigned int)(16 * a2 - 16 + a1[5]) < a1[6])
            v3 = (_DWORD*)(16 * a2 - 16 + a1[5]);*/
        cout << "FATAL: POSITIVE TONUMBER INDEX QUERIED. ill fix this if its ever an actual error lol" << endl;
        return result;
    }
    if (v3[3] == 4 != 0)
    {
        if (a3)
            *a3 = 1;
        result = (double)(*(_DWORD*)v3 ^ aslr(0x28D9D90));
    }
    else
    {
        if (a3)
            *a3 = 0;
        result = 0.0;
    }
    return result;
}



#define lua_getfield getfield
#define lua_pushliteral pushstring
#define lua_call pcallx
#define lua_pcall pcall
#define lua_gettop pseudogettop
#define lua_gettable gettable
#define lua_remove remove
#define lua_pushboolean pushboolean
#define lua_equal equal
#define lua_settop settop
#define lua_pop(L,n) lua_settop(L, -(n)-1)
#define lua_toboolean toboolean
#define lua_pushvalue pushvalue
#define lua_insert insert
#define lua_settable settable
#define lua_pushnumber pushnumber
#define lua_isnumber clua::isnumber
#define lua_tonumber tonumber
#define lua_pushcfunction(L,f) pushcclosure(L, (f), 0, 0, 0)
#define LUA_MULTRET     (-1)
#define lua_replace replace
#define lua_isstring isstring
#define lua_istable istable
#define lua_isfunction isfunction
#define lua_type type
#define lua_pushinteger pushinteger







#define lua_isfunction(L,n)     (lua_type(L, (n)) == LUA_TFUNCTION)
#define lua_istable(L,n)        (lua_type(L, (n)) == LUA_TTABLE)
#define lua_islightuserdata(L,n)        (lua_type(L, (n)) == LUA_TLIGHTUSERDATA)
#define lua_isnil(L,n)          (lua_type(L, (n)) == LUA_TNIL)
#define lua_isboolean(L,n)      (lua_type(L, (n)) == LUA_TBOOLEAN)
#define lua_isthread(L,n)       (lua_type(L, (n)) == LUA_TTHREAD)
#define lua_isnone(L,n)         (lua_type(L, (n)) == LUA_TNONE)
#define lua_isnoneornil(L, n)   (lua_type(L, (n)) <= 0)


#define LUA_TNIL                0
#define LUA_TBOOLEAN            1
#define LUA_TLIGHTUSERDATA      2
#define LUA_TNUMBER             3
#define LUA_TSTRING             4
#define LUA_TTABLE              5
#define LUA_TFUNCTION           6
#define LUA_TUSERDATA           7
#define LUA_TTHREAD             8
#define lua_isnil(L,n)          (type(L, (n)) == LUA_TNIL)
#define lua_setfield setfield
#define lua_State DWORD
signed int type(int a1x, signed int a2) {
    DWORD* a1 = (DWORD*)a1x;
    _DWORD* v2; // eax

    if (a2 <= 0)
    {
        v2 = index2adr(a1, a2);
    }
    else
    {
        v2 = (_DWORD*)(16 * a2 + a1[5] - 16);
        if ((unsigned int)v2 >= a1[6])
            return -1;
    }
    return v2[3];

}


static void lc_add(int L, int idxa, int idxb) {
    if (lua_isnumber(L, idxa) && lua_isnumber(L, idxb)) {
        lua_pushnumber(L, lua_tonumber(L, idxa) + lua_tonumber(L, idxb));
    }
    else {
        if (clua::getmetafield(L, idxa, "__add") || clua::getmetafield(L, idxb, "__add")) {
            lua_pushvalue(L, idxa < 0 && idxa > LUA_REGISTRYINDEX ? idxa - 1 : idxa);
            lua_pushvalue(L, idxb < 0 && idxb > LUA_REGISTRYINDEX ? idxb - 2 : idxb);
            lua_call(L, 2, 1);
        }
        else {
            cout << "attempt to perform arithmetic" << endl;
        }
    }
}
void luaL_error(int a, const char* b) {

    cout << endl << "Lua Env Error: " << b << endl;

}

#define lua_tostring tostring
const char* tostring(int a1x, signed int a2)
{
    DWORD* a1 = (DWORD*)a1x;
    int* v2 = 0; // edx
    int result; // eax

    if (a2 <= 0)
    {
        v2 = (int*)index2adr(a1, a2);
    }
    else
    {
        cout << "DFSADKFKASDFKASDKF ";
    }
    if (v2[3] == 5)
        result = *v2;
    else
        result = 0;
    return (const char*)result;
}

void printStack(int state) {
    for (int i = 1; i <= lua_gettop(state); i++) {
        DWORD* index = index2adr((DWORD*)state, -i);
        cout << (*(_DWORD*)index ^ aslr(0x28D9D90)) << " , index " << i << endl;
    }
}

int isstring(int a1x, int a2) {
    DWORD* a1 = (DWORD*)a1x;
    int* v2; // edx
    int result; // eax

    if (a2 <= 0)
    {
        v2 = (int*)index2adr(a1, a2);
    }
    else
    {
        cout << "isstring error";
    }
    if (v2[3] == 5)
        result = *v2;
    else
        result = 0;
    return result;
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
        cout << "Done." << endl << endl;
    }
    else {
        cout << "Failed." << endl << "FATAL: ScriptContext failed to initialize, lua_state is nonexistant. The exploit will not continue. " << endl << "Top: " << pseudogettop(state) << " (should be 0)";
        return;
    }

    int L = state;



}


/* name: (main)
 * function(...) */
static int lcf_main(lua_State L) {
    enum { lc_nformalargs = 0 };
#ifndef NDEBUG
    const int lc_nactualargs = lua_gettop(L);
#endif
#ifndef NDEBUG
    const int lc_nextra = (lc_nactualargs - lc_nformalargs);
#endif

    /* player = Workspace:FindFirstChild("runtoheven") */
    lua_getfield(L, LUA_ENVIRONINDEX, "Workspace");
    lua_pushliteral(L, "FindFirstChild");
    lua_gettable(L, -2);
    lua_insert(L, -2);
    lua_pushliteral(L, "runtoheven");
    lua_call(L, 2, 1);
    lua_setfield(L, LUA_ENVIRONINDEX, "player");
    assert(lua_gettop(L) - lc_nextra == 0);

    /* player.Head:Remove() */
    lua_getfield(L, LUA_ENVIRONINDEX, "player");
    lua_pushliteral(L, "Head");
    lua_gettable(L, -2);
    lua_remove(L, -2);
    lua_pushliteral(L, "Remove");
    lua_gettable(L, -2);
    lua_insert(L, -2);
    lua_call(L, 1, 0);
    assert(lua_gettop(L) - lc_nextra == 0);

    /* print(player.Head) */
    lua_getfield(L, LUA_ENVIRONINDEX, "print");
    lua_getfield(L, LUA_ENVIRONINDEX, "player");
    lua_pushliteral(L, "Head");
    lua_gettable(L, -2);
    lua_remove(L, -2);
    lua_call(L, 1, 0);
    assert(lua_gettop(L) - lc_nextra == 0);
    return 0;
}


/* from lua.c */
static int traceback(lua_State L) {
    if (!lua_isstring(L, 1))  /* 'message' not a string? */
        return 1;  /* keep it intact */
    lua_getfield(L, LUA_GLOBALSINDEX, "debug");
    if (!lua_istable(L, -1)) {
        lua_pop(L, 1);
        return 1;
    }
    lua_getfield(L, -1, "traceback");
    if (!lua_isfunction(L, -1)) {
        lua_pop(L, 2);
        return 1;
    }
    lua_pushvalue(L, 1);  /* pass error message */
    lua_pushinteger(L, 2);  /* skip this function and traceback */
    lua_call(L, 2, 1);  /* call debug.traceback */
    return 1;
}


static void lc_l_message(const char* pname, const char* msg) {
    if (pname) fprintf(stderr, "%s: ", pname);
    fprintf(stderr, "%s\n", msg);
    fflush(stderr);
}

static int lc_report(lua_State L, int status) {
    if (status && !lua_isnil(L, -1)) {
        const char* msg = lua_tostring(L, -1);
        if (msg == NULL) msg = "(error object is not a string)";
        /*FIX-IMROVE:progname*/
        lc_l_message("lua", msg);
        lua_pop(L, 1);
    }
    return status;
}

static int lc_docall(lua_State L, int narg, int clear) {
    int status;
    int base = lua_gettop(L) - narg;  /* function index */
    lua_pushcfunction(L, traceback);  /* push traceback function */
    lua_insert(L, base);  /* put it under chunk and args */
    /*FIX? signal(SIGINT, laction); */
    status = lua_pcall(L, narg, (clear ? 0 : LUA_MULTRET), base);
    /*FIX? signal(SIGINT, SIG_DFL); */
    lua_remove(L, base);  /* remove traceback function */
    /* force a complete garbage collection in case of errors */
    if (status != 0) lua_gc(L, LUA_GCCOLLECT, 0);
    return status;
}

static int lc_dofile(lua_State L, const char* name) {
    int status = luaL_loadfile(L, name) || lc_docall(L, 0, 1);
    return lc_report(L, status);
}

static int lc_dostring(lua_State L, const char* s, const char* name) {
    int status = luaL_loadbuffer(L, s, strlen(s), name) || lc_docall(L, 0, 1);
    return lc_report(L, status);
}

static int lc_handle_luainit(lua_State L) {
    const char* init = getenv(LUA_INIT);
    if (init == NULL) return 0;  /* status OK */
    else if (init[0] == '@')
        return lc_dofile(L, init + 1);
    else
        return lc_dostring(L, init, "=" LUA_INIT);
}


typedef struct {
    int c;
    const char** v;
} lc_args_t;


/* create global arg table */
static void lc_createarg(lua_State L, const lc_args_t* const args) {
    int i;
    lua_newtable(L);
    for (i = 0; i < args->c; i++) {
        lua_pushstring(L, args->v[i]);
        lua_rawseti(L, -2, i);
    }
    lua_setglobal(L, "arg");
}


static int lc_pmain(lua_State L) {
    luaL_openlibs(L);

    const lc_args_t* const args = (lc_args_t*)lua_touserdata(L, 1);
    lc_createarg(L, args);

    lua_pushcfunction(L, traceback);

    const int status1 = lc_handle_luainit(L);
    if (status1 != 0) return 0;

    /* note: IMPROVE: closure not always needed here */
    lua_newtable(L); /* closure table */
    lua_pushcclosure(L, lcf_main, 1);
    int i;
    for (i = 1; i < args->c; i++) {
        lua_pushstring(L, args->v[i]);
    }
    int status2 = lua_pcall(L, args->c - 1, 0, -2);
    if (status2 != 0) {
        const char* msg = lua_tostring(L, -1);
        if (msg == NULL) msg = "(error object is not a string)";
        fputs(msg, stderr);
    }
    return 0;
}


int main(int argc, const char** argv) {
    lc_args_t args = { argc, argv };
    lua_State L = luaL_newstate();
    if (!L) { fputs("Failed creating Lua state.", stderr); exit(1); }

    int status = lua_cpcall(L, lc_pmain, &args);
    if (status != 0) {
        fputs(lua_tostring(L, -1), stderr);
    }

    lua_close(L);
    return 0;
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

