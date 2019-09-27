# ironstrings
`ironstrings.py` is an IDAPython script that uses code emulation to recover constructed strings (stackstrings) from malware. The tool uses [`flare-emu`](https://github.com/fireeye/flare-emu) which combines Unicorn and IDA Pro.

This script supplements our existing tools to deal with obfuscated strings:
- [StackStrings IDA Pro Plugin](https://www.fireeye.com/blog/threat-research/2014/08/flare-ida-pro-script-series-automatic-recovery-of-constructed-strings-in-malware.html)
- [FLOSS](https://github.com/fireeye/flare-floss)

Please see the blog post at https://www.fireeye.com/blog/threat-research/2019/02/recovering-stackstrings-using-emulation-with-ironstrings.html for further details.

## Installation
### Dependencies
`ironstrings` uses `flare-emu` which requires `Unicorn`. 
- https://github.com/fireeye/flare-emu
- https://github.com/unicorn-engine/unicorn

Download and install flare-emu as described at https://github.com/fireeye/flare-emu#installation.

Note that both `flare-emu` and `ironstrings` were written using the new IDAPython API available in IDA Pro 7.0 and higher. They are not backwards compatible with previous program versions.

## Usage
To run the script in IDA Pro, go to File - Script File... (ALT+F7) and select `ironstrings.py`. The script runs automatically on all functions, prints its results to IDA Pro's output window, and adds comments at the locations where it recovered stackstrings.

`ironstrings` displays the following information about deobfusacted stackstrings in IDA Pro's output window:
- Function: Virtual function address from which the stackstring was extracted.
- Written at: Virtual address where first character of stackstring was written.
- Offset: For local stackstring, offset from the function frame at which the stackstring existed. For globalstring, offset in global memory.
- String: Deobfuscated stackstring.

An example output is shown below.

```text
Started ironstrings stackstring deobfuscation
Function           Written at         Offset             String
----------------   ----------------   ----------------   ----------------
0x4017F1           0x401830           0x40               kernel32
0x4017F1           0x401871           0x60               GetLogicalProcessorInformation
0x401AF1           0x401B2E           0x68               psapi.dll
```

An example of an annotated stackstring disassembly listing is shown below.

```asm
push    6Eh ; 'n'
pop     eax
mov     [ebp+ModuleName], ax ; stackstring: 'ntdll.dll'
push    74h ; 't'
pop     eax
mov     [ebp+var_102], ax
push    64h ; 'd'
pop     eax
mov     [ebp+var_100], ax
push    6Ch ; 'l'
pop     eax
mov     [ebp+var_FE], ax
push    6Ch ; 'l'
pop     eax
mov     [ebp+var_FC], ax
push    2Eh ; '.'
pop     eax
mov     [ebp+var_FA], ax
push    64h ; 'd'
pop     eax
mov     [ebp+var_F8], ax
push    6Ch ; 'l'
pop     eax
mov     [ebp+var_F6], ax
push    6Ch ; 'l'
pop     eax
mov     [ebp+var_F4], ax
xor     eax, eax
mov     [ebp+var_F2], ax
xor     eax, eax
mov     [ebp+var_F0], ax
lea     eax, [ebp+ModuleName]
push    eax             ; lpModuleName
call    ds:GetModuleHandleW
```

## Options
You can modify the following options at the top of the `ironstrings.py` file:

Option | Description
------ | -----------
`ANALYZE_SINGLE_FUNC` | If `True`, only analyze the currently selected function. If `False`, analyze all functions. 
`JUMP_TO_FUNC` | If `True`, jump to currently analyzed function. 
`PRINT_PLAIN_SUMMARY` | If `True`, print listing of unique stackstrings after running
`COMMENT_STACKSTRINGS` | If `True`, add comments for recovered stackstrings
`COMMENT_STACKSTRING_GLOBAL_REPEATABLE` | If `True`, add a repeatable comment at the global memory address. If `False`, add comment where string was constructed.
`COMMENT_STACKSTRING_PREFIX` | String used as prefix for stackstring comments.
`COMMENT_STACKSTRING_SUFFIX` | String used as suffix for stackstring comments.
