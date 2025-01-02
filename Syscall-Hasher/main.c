#include <Windows.h>
#include <stdio.h>


#define SEED        0xEDB88320
#define STR         "_CRC32"

unsigned int crc32b(char* str) {

    unsigned int    byte, mask, crc = 0xFFFFFFFF;
    int             i = 0, j = 0;

    while (str[i] != 0) {
        byte = str[i];
        crc = crc ^ byte;

        for (j = 7; j >= 0; j--) {
            mask = -1 * (crc & 1);
            crc = (crc >> 1) ^ (SEED & mask);
        }

        i++;
    }
    return ~crc;
}


#define HASH(API) crc32b((char*)API)


int main() {

    printf("#define %s%s \t 0x%0.8X \n", "NtCreateUserProcess", STR, HASH("NtCreateUserProcess"));
    printf("#define %s%s \t 0x%0.8X \n", "NtAllocateVirtualMemory", STR, HASH("NtAllocateVirtualMemory"));
    printf("#define %s%s \t 0x%0.8X \n", "NtWriteVirtualMemory", STR, HASH("NtWriteVirtualMemory"));
    printf("#define %s%s \t 0x%0.8X \n", "NtProtectVirtualMemory", STR, HASH("NtProtectVirtualMemory"));
    printf("#define %s%s \t 0x%0.8X \n", "NtQueueApcThread", STR, HASH("NtQueueApcThread"));
    printf("#define %s%s \t 0x%0.8X \n", "NtCreateThreadEx", STR, HASH("NtCreateThreadEx"));
    printf("#define %s%s \t 0x%0.8X \n", "NtQuerySystemInformation", STR, HASH("NtQuerySystemInformation"));
    printf("#define %s%s \t 0x%0.8X \n", "NtDelayExecution", STR, HASH("NtDelayExecution"));

    //\
    printf("#define %s%s \t 0x%0.8X \n", "", STR, HASH(""));
}
