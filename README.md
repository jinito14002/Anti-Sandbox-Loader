# Anti-Sandbox-Loader
An PoC loader with anti-debug and anti-VM capabilities for personal education purposes.

Contains a meterpreter payload as a temporary placement.

It was undetectable on VT for at least 2-3 weeks. 
First uploaded on 2023/7, was detected by 0/71 engines.

(https://www.virustotal.com/gui/file/27130858b27af3b4231ef5ba308e6502d02702355169821cc0d5c57ff79e503e/detection)

# Features
 - Hashed syscall APIs with CRC-32
 - Encrypt/Decrypt payload with RC4 (key is stored in encrypted form inside the binary)
     - Decrypt the key by brute forcing to search to match a specific first byte
 - Obfuscate payload bytes as ipv4 addresses (252.72.131.228 → 0xFC 0x7B 0x48 0xE4)      
 - Dynamically resolves "syscall" assembly instruction from ntdll.dll address space (Hell's Gate)
 - Dynamically resolve syscall System Service Numbers (Hell's Gate)
 - Process injection with dynamic syscalls (NtCreateUserProcess, NtAllocateVirtualMemory, NtWriteVirtualMemory, NtProtectVirtualMemory. NtCreateThreadEx)
 - Anti-Debug with
     - Process name check
     - PEB being debugged flag check
 - Anti-VM
     - Display Resolution check
     - Filename is not a hash check
     - Process number check
     - Mouse click check
     - Slow down execution with NtDelayExecution

# How to use
Use the Encryption and Syscall-Hasher to encrypt the payload and hashes for direct syscalls.
