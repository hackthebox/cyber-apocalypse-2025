from pwn import *
import capstone
import sys
import ctypes

def xor(a, b):
    return bytes([a ^ b for a, b in zip(a, b)])

# tells you how many bytes forward also
def disas_single(data):
    disas = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    inst = next(disas.disasm(data, 0))
    return inst, inst.size, inst.mnemonic

def deobufscate(elf, code, text_off, text_end, addr, modified):
    stop = False
    while not stop:
        inst, sz, mneumonic = disas_single(code[addr:])
        if mneumonic == 'ret':
            stop = True
        elif mneumonic == 'call':
            call_dst = addr + ctypes.c_int64(int(inst.op_str, 16)).value
            if call_dst >= text_off and call_dst <= text_end:
                deobufscate(elf, code, text_off, text_end, call_dst, modified)
        elif mneumonic == 'xor':
            if '[rip + ' in inst.op_str:
                rip_rel = int(inst.op_str.split('[rip + ')[1].split(']')[0], 16)
                key = int(inst.op_str.split(',')[1], 16)
                decrypt = b''
                if inst.op_str.startswith('qword ptr '):
                    decrypt = xor(p64(key), code[addr + sz + rip_rel: addr + sz + rip_rel + 8])
                elif inst.op_str.startswith('dword ptr '):
                    decrypt = xor(p32(key), code[addr + sz + rip_rel: addr + sz + rip_rel + 4])
                elif inst.op_str.startswith('word ptr '):
                    decrypt = xor(p16(key), code[addr + sz + rip_rel: addr + sz + rip_rel + 2])
                elif inst.op_str.startswith('byte ptr '):
                    decrypt = xor(p8(key), code[addr + sz + rip_rel: addr + sz + rip_rel + 1])
                assert(len(decrypt) in [1, 2, 4, 8])
                for i, b in enumerate(decrypt):
                    modified[addr + sz + rip_rel + i] = b
                for i in range(addr, addr + sz):
                    modified[i] = 0x90
                if code[addr - 0x1] == 0x9c:
                    modified[addr - 0x1] = 0x90
                if code[addr + sz] == 0x9d:
                    modified[addr + sz] = 0x90
            elif '[rip -' in inst.op_str:
                for i in range(addr, addr + sz):
                    modified[i] = 0x90
                if code[addr - 0x1] == 0x9c:
                    modified[addr - 0x1] = 0x90
                if code[addr + sz] == 0x9d:
                    modified[addr + sz] = 0x90
            code = bytes(modified)
        addr += sz


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print(f'{sys.argv[0]} obfuscated main_offset')
        exit(1)
    elf = ELF(sys.argv[1])
    main = int(sys.argv[2], 16)
    text_off = elf.get_section_by_name('.text').header.sh_offset
    text_end = elf.get_section_by_name('.text').header.sh_offset + elf.get_section_by_name('.text').header.sh_size
    sz = text_off + text_end
    with open(elf.path, 'rb') as f:
        full = f.read()
    data = full[:sz]
    modified = bytearray(data)
    deobufscate(elf, data, text_off, text_end, main, modified)
    with open(f'{elf.path}_deobfuscate', 'wb') as f:
        f.write(bytes(modified) + full[sz:])
