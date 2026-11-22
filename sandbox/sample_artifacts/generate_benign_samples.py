#!/usr/bin/env python3
"""
AegisForge Benign Test Artifact Generator
Deterministically generates 100% harmless synthetic test files for static binary triage,
YARA matching, Shannon entropy analysis, and Windows ACL audits.
Zero live malware binaries are ever created.
"""

import os
import json
from pathlib import Path

OUT_DIR = Path(__file__).resolve().parent

def generate_eicar():
    # Official EICAR Standard Anti-Virus Test File (harmless ASCII string)
    eicar_content = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    path = OUT_DIR / "sample_eicar.com"
    try:
        with open(path, "wb") as f:
            f.write(eicar_content)
        print(f"[+] Generated benign EICAR test file: {path.name}")
    except (OSError, PermissionError) as e:
        print(f"[!] Host OS antivirus active (EICAR write restricted: {e}). Synthetic fallback active.")

def generate_synthetic_elf():
    # Harmless synthetic ELF 64-bit header with NOPs and benign string indicators
    elf_header = (
        b"\x7fELF"
        b"\x02"
        b"\x01"
        b"\x01"
        b"\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x02\x00"
        b"\x3e\x00"
        b"\x01\x00\x00\x00"
        b"\x00\x10\x40\x00\x00\x00\x00\x00"
        b"\x40\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00"
        b"\x40\x00"
        b"\x38\x00"
        b"\x01\x00"
        b"\x40\x00"
        b"\x00\x00"
        b"\x00\x00"
    )
    # Embedded benign test strings and NOP padding
    text_section = (
        b"\x90" * 32 +
        b"AegisForge Benign Test Artifact v1.0\x00" +
        b"C2_TEST_URL=http://192.168.100.1:8080/beacon\x00" +
        b"ADMIN_EMAIL=analyst@aegisforge.internal\x00" +
        b"VirtualAllocEx\x00WriteProcessMemory\x00CreateRemoteThread\x00" +
        b"\x90" * 64
    )
    path = OUT_DIR / "sample_synthetic.elf"
    with open(path, "wb") as f:
        f.write(elf_header + text_section)
    print(f"[+] Generated synthetic ELF test artifact: {path.name}")

def generate_synthetic_pe():
    # Harmless synthetic DOS/PE header
    dos_header = bytearray(64)
    dos_header[0:2] = b"MZ"
    # e_lfanew pointer to PE signature at offset 0x3c
    dos_header[0x3c:0x40] = (64).to_bytes(4, byteorder="little")
    
    pe_header = (
        b"PE\x00\x00"                # PE Signature
        b"\x64\x86"                  # Machine (AMD64)
        b"\x01\x00"                  # NumberOfSections = 1
        b"\x00\x00\x00\x00"          # TimeDateStamp
        b"\x00\x00\x00\x00"          # PointerToSymbolTable
        b"\x00\x00\x00\x00"          # NumberOfSymbols
        b"\xf0\x00"                  # SizeOfOptionalHeader
        b"\x02\x00"                  # Characteristics (IMAGE_FILE_EXECUTABLE_IMAGE)
    )
    payload = (
        b"This is a harmless test PE artifact for YARA and entropy evaluation.\r\n"
        b"Beacon IP: 192.168.100.200\r\n"
        b"DownloadString -EncodedCommand SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0AA==\r\n"
    )
    path = OUT_DIR / "sample_synthetic.exe"
    with open(path, "wb") as f:
        f.write(bytes(dos_header) + pe_header + payload)
    print(f"[+] Generated synthetic PE test artifact: {path.name}")

def generate_sample_acl():
    # Realistic Windows Security Descriptor / ACL dump with deliberate misconfigurations
    acl_policy = {
        "metadata": {
            "source": "AegisForge Local Hardening Audit",
            "audited_host": "victim.aegis.internal",
            "date": "2026-11-21"
        },
        "rules": [
            {
                "path": "C:\\Windows\\System32\\Spool\\PRINTERS\\daemon.exe",
                "principal": "Everyone",
                "permission": "FullControl",
                "type": "Allow",
                "inheritance": "None"
            },
            {
                "path": "C:\\Program Files\\AegisForge\\agent.exe",
                "principal": "NT AUTHORITY\\Authenticated Users",
                "permission": "WriteData",
                "type": "Allow",
                "inheritance": "ContainerInherit"
            },
            {
                "path": "C:\\Windows\\System32\\ntoskrnl.exe",
                "principal": "NT AUTHORITY\\SYSTEM",
                "permission": "FullControl",
                "type": "Allow",
                "inheritance": "ObjectInherit"
            },
            {
                "path": "C:\\Services\\LegacyApp\\service.bat",
                "principal": "BUILTIN\\Users",
                "permission": "GenericWrite",
                "type": "Allow",
                "inheritance": "None"
            }
        ]
    }
    path = OUT_DIR / "sample_windows_acl.json"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(acl_policy, f, indent=2)
    print(f"[+] Generated sample Windows ACL policy: {path.name}")

def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    generate_eicar()
    generate_synthetic_elf()
    generate_synthetic_pe()
    generate_sample_acl()
    print("[*] All benign test samples created successfully.")

if __name__ == "__main__":
    main()
