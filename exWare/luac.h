#pragma once

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
#include "retcheck.h"
using namespace std;
#define _CRT_SECURE_NO_DEPRICATE
#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#define _DWORD DWORD


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
#define lua_toboolean toboolean
#define lua_pushvalue pushvalue
#define lua_insert insert
#define lua_settable settable
#define lua_pushnumber pushnumber
#define lua_setfield setfield
#define lua_isnumber clua::isnumber
#define lua_tonumber tonumber
#define LUA_MULTRET     (-1)
#define lua_replace replace
#define lua_isstring isstring
#define lua_istable istable
#define lua_isfunction isfunction
#define lua_type type
#define lua_pushinteger pushinteger
#define lua_pushcclosure pushcclosure
#define lua_newtable newtable
#define lua_newtable(L)         lua_createtable(L, 0, 0)
#define lua_pushcfunction(L,f)  pushcclosure(L, (f), 0)
#define lua_pop(L,n)            lua_settop(L, -(n)-1)






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
#define lua_State DWORD

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
    int createtable_s = aslr(0x0135FF30);
    int rawseti_s = aslr(0x13613A0);
    int touserdata_s = aslr(0x1361FB0);
}
namespace clua {
    typedef int(__stdcall* clua_getfield)(int, int, const char*);
    clua_getfield getfield = (clua_getfield)address::getfield_s;

    typedef int(__fastcall* clua_pushstring)(int, const char*);
    clua_pushstring pushstring = (clua_pushstring)address::pushstring_s;

    typedef int(__cdecl* clua_pcall)(int, int, int, int);
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

    typedef int* (__cdecl* clua_pushinteger)(int, int);
    clua_pushinteger pushinteger = (clua_pushinteger)address::pushinteger_s;

    typedef int(__cdecl* clua_gc)(int, int, int);
    clua_gc gc = (clua_gc)address::gc_s;

    typedef int(__cdecl* clua_createtable)(int, int, int);
    clua_createtable createtable = (clua_createtable)address::createtable_s;

    typedef int(__cdecl* clua_rawseti)(int, int, int);
    clua_rawseti rawseti = (clua_rawseti)address::rawseti_s;


    typedef int(__cdecl* clua_touserdata)(int, int);
    clua_touserdata touserdata = (clua_touserdata)address::touserdata_s;




}
#define lua_touserdata clua::touserdata
void getfield(int a1, int a2, const char* a3) {
    retcheck::checkRetcheck(address::getfield_s);
    clua::getfield(a1, a2, a3);
    retcheck::checkRetcheck(address::getfield_s);
}

void createtable(int a1, int a2, int a3) {
    retcheck::checkRetcheck(address::createtable_s);
    clua::createtable(a1, a2, a3);
    retcheck::checkRetcheck(address::createtable_s);
}

void rawseti(int a1, int a2, int a3) {
    retcheck::checkRetcheck(address::rawseti_s);
    clua::rawseti(a1, a2, a3);
    retcheck::checkRetcheck(address::rawseti_s);
}

void pushinteger(int a1, int a2) {
    retcheck::checkRetcheck(address::pushinteger_s);
    clua::pushinteger(a1, a2);
    retcheck::checkRetcheck(address::pushinteger_s);
}

void gc(int a1, int a2, int a3) {
    retcheck::checkRetcheck(address::gc_s);
    clua::gc(a1, a2, a3);
    retcheck::checkRetcheck(address::gc_s);
}

void pushcclosure(int a1, int a2, int a3) {
    retcheck::checkRetcheck(address::pushcclosure_s);
    clua::pushcclosure(a1, a2, a3, 0, 0);
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
int pcall(int a1, int a2, int a3, int a4) {
    retcheck::checkRetcheck(address::pcall_s);
    int x = clua::pcall(a1, a2, a3, a4);
    retcheck::checkRetcheck(address::pcall_s);
    return x;
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

int pseudogettop(int state) {
    return (*(DWORD*)(state + 24) - *(DWORD*)(state + 20)) >> 4;
}

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
    int* v2 = 0; // edx
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







#define LUA_GCSTOP              0
#define LUA_GCRESTART           1
#define LUA_GCCOLLECT           2
#define LUA_GCCOUNT             3
#define LUA_GCCOUNTB            4
#define LUA_GCSTEP              5
#define LUA_GCSETPAUSE          6
#define LUA_GCSETSTEPMUL        7
#define lua_gc gc

#define lua_createtable createtable
#define lua_pushstring pushstring
#define lua_getglobal(a,b) lua_getfield(a,-10002,b)
#define lua_rawseti rawseti
#define lua_setglobal(a,b) setfield(a, -10002, b)


