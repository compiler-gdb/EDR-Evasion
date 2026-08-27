module;
#include<windows.h>

export module Auditor.Syscall;
import Auditor.PE;

export namespace Auditor{
	namespace Syscall {

		WORD GetSyscallNumber(void* functionAddress) {
			if (!functionAddress) return 0;

			BYTE* opcode = (BYTE*)functionAddress;

			if(opcode[0] == 0x4c && opcode[1] == 0x8B && opcode[2] == 0xD1){  
				if(opcode[3] == 0xB8){ 
					WORD syscallNumber = *(WORD*)&opcode[4];
					return syscallNumber;
				}
			}

			return 0;
		}

		extern "C" NTSTATUS DirectSyscallInvoke(DWORD ssn, ...);
	}
}