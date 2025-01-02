#include <Windows.h>
#include <stdio.h>

// Take in Literal Wide Character string, convert it to BYTES and XOR
XorStringObfuscate(IN LPCWSTR String) {

    int length = lstrlenW(String);

    // Calculate the required buffer size for the byte array
    int bufferSize = WideCharToMultiByte(CP_UTF8, 0, String, length, NULL, 0, NULL, NULL);

    // Allocate memory for the byte array
    BYTE* bytes = (BYTE*)malloc(bufferSize);

    // Convert the wide characters to bytes
    WideCharToMultiByte(CP_UTF8, 0, String, length, (LPSTR)bytes, bufferSize, NULL, NULL);

    printf("unsigned char %.*s[] = { ", (bufferSize - 4), bytes);
    for (int i = 0; i < bufferSize; i++) {
        // Perform XOR
        bytes[i] = bytes[i] ^ 0xEA;
        printf("0x%x", bytes[i]);
        if (i < (bufferSize - 1))
            printf(", ");
    }
    printf("};\n");
}