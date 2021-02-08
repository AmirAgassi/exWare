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

#include "luac.h"
#include "retcheck.h"
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



string int2hex(int addr) {
    std::stringstream stream;
    stream << std::hex << std::uppercase << addr;
    std::string result(stream.str());
    return result;
}



int getstate(DWORD ScriptContext) {
    return *(DWORD*)(ScriptContext + 180) ^ (ScriptContext + 180);
}

int main() {

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
        return 0;
    }

    int L = state;

    lc_args_t args = { NULL, NULL };
    if (!L) { fputs("Failed creating Lua state.", stderr); exit(1); }

    int status = lua_cpcall(L, lc_pmain, &args);
    if (status != 0) {
        fputs(lua_tostring(L, -1), stderr);
    }

    return 0;

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

