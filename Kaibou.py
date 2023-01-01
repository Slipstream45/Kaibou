import pefile
import sys

def check_security(filename):
    pe = pefile.PE(filename)

    # Check for ASLR
    if hasattr(pe, 'OPTIONAL_HEADER'):
        optional_header = pe.OPTIONAL_HEADER
        if optional_header.DllCharacteristics & 0x40:
            print('ASLR is enabled')
        else:
            print('ASLR is not enabled')
    else:
        print('PE file does not have an optional header')

    # Check for DEP
    if hasattr(pe, 'OPTIONAL_HEADER'):
        optional_header = pe.OPTIONAL_HEADER
        if optional_header.DllCharacteristics & 0x100:
            print('DEP is enabled')
        else:
            print('DEP is not enabled')
    else:
        print('PE file does not have an optional header')

    # Check for executable stack
    if hasattr(pe, 'OPTIONAL_HEADER'):
        optional_header = pe.OPTIONAL_HEADER
        if optional_header.DllCharacteristics & 0x200:
            print('Executable stack is enabled')
        else:
            print('Executable stack is not enabled')
    else:
        print('PE file does not have an optional header')

    # Print memory regions with read, write, and execute permissions
    print('Memory regions:')
    for section in pe.sections:
        permissions = ''
        if section.Characteristics & 0x80000000:
            permissions += 'R'
        if section.Characteristics & 0x40000000:
            permissions += 'W'
        if section.Characteristics & 0x20000000:
            permissions += 'X'
        if permissions:
            print(f'{section.Name.decode("utf-8")}: {permissions}')

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('Usage: Kaibou.py <filename>')
        sys.exit(1)

    check_security(sys.argv[1])
