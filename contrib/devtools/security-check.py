#!/usr/bin/env python3
'''
Perform basic security checks on a series of executables.
Exit status will be 0 if successful, and the program will be silent.
Otherwise the exit status will be 1 and it will log which executables failed which checks.
Needs `readelf` (for ELF), `objdump` (for PE) and `otool` (for MACHO).
'''
#from __future__ import division,print_function,unicode_literals
import subprocess
import sys
import os

from typing import List, Optional

READELF_CMD = os.getenv('READELF', '/usr/bin/readelf')
OBJDUMP_CMD = os.getenv('OBJDUMP', '/usr/bin/objdump')
OTOOL_CMD = os.getenv('OTOOL', '/usr/bin/otool')

def run_command(command) -> str:
    p = subprocess.run(command, stdout=subprocess.PIPE, check=True, universal_newlines=True)
    return p.stdout

def check_ELF_PIE(executable) -> bool:
    '''
    Check for position independent executable (PIE), allowing for address space randomization.
    '''
    stdout = run_command([READELF_CMD, '-h', '-W', executable])

    ok = False
    for line in stdout.splitlines():
        tokens = line.split()
        if len(line)>=2 and tokens[0] == 'Type:' and tokens[1] == 'DYN':
            ok = True
    return ok

def get_ELF_program_headers(executable):
    '''Return type and flags for ELF program headers'''
    stdout = run_command([READELF_CMD, '-l', '-W', executable])

    in_headers = False
    count = 0
    headers = []
    for line in stdout.split(b'\n'):
        if line.startswith(b'Program Headers:'):
            in_headers = True
        if line == b'':
            in_headers = False
        if in_headers:
            if count == 1: # header line
                ofs_typ = line.find(b'Type')
                ofs_offset = line.find(b'Offset')
                ofs_flags = line.find(b'Flg')
                ofs_align = line.find(b'Align')
                if ofs_typ == -1 or ofs_offset == -1 or ofs_flags == -1 or ofs_align  == -1:
                    raise ValueError('Cannot parse elfread -lW output')
            elif count > 1:
                typ = line[ofs_typ:ofs_offset].rstrip()
                flags = line[ofs_flags:ofs_align].rstrip()
                headers.append((typ, flags))
            count += 1
    return headers

def check_ELF_NX(executable) -> bool:
    '''
    Check that no sections are writable and executable (including the stack)
    '''
    have_wx = False
    have_gnu_stack = False
    for (typ, flags) in get_ELF_program_headers(executable):
        if typ == b'GNU_STACK':
            have_gnu_stack = True
        if b'W' in flags and b'E' in flags: # section is both writable and executable
            have_wx = True
    return have_gnu_stack and not have_wx

def check_ELF_RELRO(executable) -> bool:
    '''
    Check for read-only relocations.
    GNU_RELRO program header must exist
    Dynamic section must have BIND_NOW flag
    '''
    have_gnu_relro = False
    for (typ, flags) in get_ELF_program_headers(executable):
        # Note: not checking flags == 'R': here as linkers set the permission differently
        # This does not affect security: the permission flags of the GNU_RELRO program
        # header are ignored, the PT_LOAD header determines the effective permissions.
        # However, the dynamic linker need to write to this area so these are RW.
        # Glibc itself takes care of mprotecting this area R after relocations are finished.
        # See also http://permalink.gmane.org/gmane.comp.gnu.binutils/71347
        if typ == b'GNU_RELRO':
            have_gnu_relro = True

    have_bindnow = False
    stdout = run_command([READELF_CMD, '-d', '-W', executable])

    for line in stdout.splitlines():
        tokens = line.split()
        if len(tokens)>1 and tokens[1] == b'(BIND_NOW)' or (len(tokens)>2 and tokens[1] == b'(FLAGS)' and b'BIND_NOW' in tokens[2]):
            have_bindnow = True
    return have_gnu_relro and have_bindnow

def check_ELF_Canary(executable) -> bool:
    '''
    Check for use of stack canary
    '''
    stdout = run_command([READELF_CMD, '--dyn-syms', '-W', executable])

    ok = False
    for line in stdout.split(b'\n'):
        if b'__stack_chk_fail' in line:
            ok = True
    return ok

def get_PE_dll_characteristics(executable) -> int:
    '''Get PE DllCharacteristics bits'''
    stdout = run_command([OBJDUMP_CMD, '-x',  executable])

    bits = 0
    for line in stdout.splitlines():
        tokens = line.split()
        if len(tokens)>=2 and tokens[0] == 'DllCharacteristics':
            bits = int(tokens[1],16)
    return bits

IMAGE_DLL_CHARACTERISTICS_HIGH_ENTROPY_VA = 0x0020
IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE    = 0x0040
IMAGE_DLL_CHARACTERISTICS_NX_COMPAT       = 0x0100

def check_PE_DYNAMIC_BASE(executable) -> bool:
    '''PIE: DllCharacteristics bit 0x40 signifies dynamicbase (ASLR)'''
    bits = get_PE_dll_characteristics(executable)
    return (bits & IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE) == IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE

# Must support high-entropy 64-bit address space layout randomization
# in addition to DYNAMIC_BASE to have secure ASLR.
def check_PE_HIGH_ENTROPY_VA(executable) -> bool:
    '''PIE: DllCharacteristics bit 0x20 signifies high-entropy ASLR'''
    bits = get_PE_dll_characteristics(executable)
    return (bits & IMAGE_DLL_CHARACTERISTICS_HIGH_ENTROPY_VA) == IMAGE_DLL_CHARACTERISTICS_HIGH_ENTROPY_VA

def check_PE_RELOC_SECTION(executable) -> bool:
    '''Check for a reloc section. This is required for functional ASLR.'''
    stdout = run_command([OBJDUMP_CMD, '-h',  executable])

    for line in stdout.splitlines():
        if '.reloc' in line:
            return True
    return False

def check_PE_NX(executable) -> bool:
    '''NX: DllCharacteristics bit 0x100 signifies nxcompat (DEP)'''
    bits = get_PE_dll_characteristics(executable)
    return (bits & IMAGE_DLL_CHARACTERISTICS_NX_COMPAT) == IMAGE_DLL_CHARACTERISTICS_NX_COMPAT

def get_MACHO_executable_flags(executable) -> List[str]:
    stdout = run_command([OTOOL_CMD, '-vh', executable])

    flags = []
    for line in stdout.splitlines():
        tokens = line.split()
        # filter first two header lines
        if 'magic' in tokens or 'Mach' in tokens:
            continue
        # filter ncmds and sizeofcmds values
        flags += [t for t in tokens if not t.isdigit()]
    return flags

def check_MACHO_PIE(executable) -> bool:
    '''
    Check for position independent executable (PIE), allowing for address space randomization.
    '''
    flags = get_MACHO_executable_flags(executable)
    if 'PIE' in flags:
        return True
    return False

def check_MACHO_NOUNDEFS(executable) -> bool:
    '''
    Check for no undefined references.
    '''
    flags = get_MACHO_executable_flags(executable)
    if 'NOUNDEFS' in flags:
        return True
    return False

def check_MACHO_NX(executable) -> bool:
    '''
    Check for no stack execution
    '''
    flags = get_MACHO_executable_flags(executable)
    if 'ALLOW_STACK_EXECUTION' in flags:
        return False
    return True

def check_MACHO_LAZY_BINDINGS(executable) -> bool:
    '''
    Check for no lazy bindings.
    We don't use or check for MH_BINDATLOAD. See #18295.
    '''
    stdout = run_command([OTOOL_CMD, '-l', executable])

    for line in stdout.splitlines():
        tokens = line.split()
        if 'lazy_bind_off' in tokens or 'lazy_bind_size' in tokens:
            if tokens[1] != '0':
                return False
    return True

def check_MACHO_Canary(executable) -> bool:
    '''
    Check for use of stack canary
    '''
    stdout = run_command([OTOOL_CMD, '-Iv', executable])

    ok = False
    for line in stdout.splitlines():
        if '___stack_chk_fail' in line:
            ok = True
    return ok

CHECKS = {
'ELF': [
    ('PIE', check_ELF_PIE),
    ('NX', check_ELF_NX),
    ('RELRO', check_ELF_RELRO),
    ('Canary', check_ELF_Canary)
],
'PE': [
    ('DYNAMIC_BASE', check_PE_DYNAMIC_BASE),
    ('HIGH_ENTROPY_VA', check_PE_HIGH_ENTROPY_VA),
    ('NX', check_PE_NX),
    ('RELOC_SECTION', check_PE_RELOC_SECTION)
],
'MACHO': [
    ('PIE', check_MACHO_PIE),
    ('NOUNDEFS', check_MACHO_NOUNDEFS),
    ('NX', check_MACHO_NX),
    ('LAZY_BINDINGS', check_MACHO_LAZY_BINDINGS),
    ('Canary', check_MACHO_Canary)
]
}

def identify_executable(executable) -> Optional[str]:
    with open(filename, 'rb') as f:
        magic = f.read(4)
    if magic.startswith(b'MZ'):
        return 'PE'
    elif magic.startswith(b'\x7fELF'):
        return 'ELF'
    elif magic.startswith(b'\xcf\xfa'):
        return 'MACHO'
    return None

if __name__ == '__main__':
    retval = 0
    for filename in sys.argv[1:]:
        try:
            etype = identify_executable(filename)
            if etype is None:
                print('%s: unknown format' % filename)
                retval = 1
                continue

            failed = []
            for (name, func) in CHECKS[etype]:
                if not func(filename):
                    failed.append(name)
            if failed:
                print('%s: failed %s' % (filename, ' '.join(failed)))
                retval = 1
        except IOError:
            print('%s: cannot open' % filename)
            retval = 1
    exit(retval)

