# exWare
 A modern CLVM script execution exploit challenging Roblox's new security and integrity checks.
 
exWare 
 
Further details coming later. Exploit projected to be completed ~Q1 2022, I am not good at this.

Console uses freopen, add "_CRT_SECURE_NO_WARNINGS" to your IDE's C/C++ Preprocessor definitions.

# CLVM information from my previous project, Danghui

The CLVM's objective is to achieve script execution through a custom virtual machine that operates on a foreign, untranslated and incompatable lua state. It copies the Lua C functions from Roblox to a seperate DLL, and does everything *WITHOUT BYPASSING ANY MAJOR CHECKS. (memcheck, retcheck, hookcheck, etc)*. This is an amazing solution to executing code compared to proto conversion/bytecode conversion, as it rarely touches anything in Roblox's memory, and rarely calls any Roblox functions externally, while outsourcing all of the execution work to the local lua_state. 

The CLVM achieves all of the above by only compiling all of the lua code on it's own external lua state. The operations are then saved, wrapped into Roblox's implementation of every opcode, and executed in order. Addressed below in the "Issues" row, a few opcodes cannot follow this procedure due to their own complications, they must be manually mapped. The code execution mainly happens in the simplified code below. The instructions are recieved, and for each instruction, an action is assigned and executed, then the cycle repeats for each instruction following until the script has been completed.

```C++
Instruction *i = f->code; 
for (;;)
 i++;
 switch (get_opcode(*i))
 case OP_SETGLOBAL:
  // execute Roblox's modified OP_SETGLOBAL
 case OP_ADD:
  // execute Roblox's modified OP_ADD
 case OP_CALL:
  // execute Roblox's modified OP_CALL
 ```

- Able to index every class
- Able to set any property
- Calling all Roblox functions
- Roblox API functions all work, including require, RbxUtility, and LoadLibrary, with *no manual modifications!*
- Accessing all Roblox global tables
- Context level 7, acecess to CoreGUI, ScriptContext, etc.
- YieldFunction's have native support, isn't that just great?
- NO YIELDING, NO HTTP/LOADSTRING SUPPORT.

