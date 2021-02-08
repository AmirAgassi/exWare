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


#define aslr(x)(x - 0x400000 + (DWORD)GetModuleHandleA(0))


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
