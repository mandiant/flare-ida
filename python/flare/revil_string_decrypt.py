############################################
# Copyright (C) 2021 FireEye, Inc.
#
# Author: Chuong Dong
#
# revil_string_decrypt is an IDAPython script that uses flare-emu (which combines Unicorn and
# IDA Pro) to automate string decryption for REvil ransomware samples.
#
# Dependencies:
# https://github.com/fireeye/flare-emu
############################################

from arc4 import ARC4
import idaapi, idc, idautils
import flare_emu
import idc
import idaapi

def RC4_crypt(key, buffer):
    arc4 = ARC4(key)
    
    result = list(arc4.decrypt(buffer))
    string_result = ''
    for each in result:
        if each != 0:
            string_result += chr(each)
    return string_result

def decode_callback(eh, address, argv, userData):
    encoded_str_ea = eh.getRegVal('edx')
    ENCRYPTED_STRING_BUFFER = argv[0]
    key_offset = argv[1]
    key_length = argv[2]
    data_length = argv[3]

    
    RC4_key = idaapi.get_bytes(ENCRYPTED_STRING_BUFFER + key_offset, key_length)
    RC4_encrypted_buffer = idaapi.get_bytes(ENCRYPTED_STRING_BUFFER + key_offset + key_length, data_length)
    decrypted_str = RC4_crypt(RC4_key, RC4_encrypted_buffer)
    print(hex(address) + ' ' + decrypted_str)
    eh.analysisHelper.setComment(address, decrypted_str, False)

eh = flare_emu.EmuHelper()

# Change "string_decrypt" to the string decryption function name on IDA Pro
eh.iterate(eh.analysisHelper.getNameAddr("string_decrypt"), decode_callback)
