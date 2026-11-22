# AegisForge Sandbox Targets Makefile
# Demonstrates protected vs unprotected compilation flags for educational analysis

CC = gcc
CFLAGS_COMMON = -Wall -O0 -g

all: stack_lab_unprotected stack_lab_hardened

# 1. Unprotected binary: No canary, executable stack, no PIE
stack_lab_unprotected: stack_lab.c
	$(CC) $(CFLAGS_COMMON) -fno-stack-protector -z execstack -no-pie -o stack_lab_unprotected stack_lab.c

# 2. Hardened binary: Stack canary, non-executable stack (NX), PIE, Full RELRO
stack_lab_hardened: stack_lab.c
	$(CC) $(CFLAGS_COMMON) -fstack-protector-strong -Wl,-z,noexecstack -fPIE -pie -Wl,-z,relro,-z,now -o stack_lab_hardened stack_lab.c

clean:
	rm -f stack_lab_unprotected stack_lab_hardened
