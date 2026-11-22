/**
 * AegisForge Educational Vulnerable Target
 * Stack Buffer Overflow & Compiler Mitigation Study Lab
 *
 * This binary is designed strictly for local educational study
 * in an isolated sandbox to demonstrate how stack protections work:
 *
 * Compilation Modes:
 *   1. Vulnerable (Unprotected):
 *      gcc -fno-stack-protector -z execstack -no-pie -o stack_lab_unprotected stack_lab.c
 *
 *   2. Hardened (Industry Standard Mitigations):
 *      gcc -fstack-protector-strong -Wl,-z,noexecstack -fPIE -pie -Wl,-z,relro,-z,now -o stack_lab_hardened stack_lab.c
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void secret_diagnostic_console(void) {
    printf("[!] SECURITY NOTICE: Control flow redirected to diagnostic console!\n");
    printf("[*] In an unprotected environment, an attacker could hijack EIP/RIP.\n");
    printf("[*] Mitigations like Stack Canaries and ASLR prevent this redirection.\n");
}

void vulnerable_function(const char *user_input) {
    char local_buffer[32]; // Fixed 32-byte buffer on the stack
    
    printf("[+] Allocated 32 bytes for local_buffer at %p\n", (void*)local_buffer);
    printf("[+] Received input of length: %zu bytes\n", strlen(user_input));
    
    // UNSAFE: strcpy does not check destination buffer boundaries!
    // If user_input > 32 bytes:
    //   1. Overwrites buffer
    //   2. Overwrites compiler alignment padding
    //   3. Corrupts Stack Canary (if compiled with -fstack-protector)
    //   4. Overwrites Saved Frame Pointer (EBP/RBP)
    //   5. Overwrites Saved Return Address (EIP/RIP)
    strcpy(local_buffer, user_input);
    
    printf("[+] Content copied successfully. Function exiting normally...\n");
}

int main(int argc, char *argv[]) {
    printf("============================================================\n");
    printf("  AegisForge Educational Stack Corruption & Mitigation Lab  \n");
    printf("============================================================\n");
    
    if (argc < 2) {
        printf("Usage: %s <input_string>\n", argv[0]);
        printf("Example: %s $(python3 -c 'print(\"A\" * 48)')\n", argv[0]);
        return 1;
    }
    
    vulnerable_function(argv[1]);
    printf("[+] Main function completed cleanly.\n");
    return 0;
}
