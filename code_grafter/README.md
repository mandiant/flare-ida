# Code Grafter Function Replacements

## About Code Grafter
Code Grafter is an IDA Python script that makes it possible to use IDA Pro's
[Bochs IDB Mode](https://www.hex-rays.com/products/ida/support/idadoc/1331.shtml)
to emulate code that imports Windows API functions. Emulation environments
like Bochs IDB mode do not resolve or emulate imported functions, resulting
in exceptions and inability to use emulation with certain code. Code Grafter
solves this for a subset of Windows API functions by inserting opcodes and
data to implement a small subset of imported Windows API functions. Code
Grafter targets functions with trivial implementations that that are commonly
associated with string decoding and malware unpacking. Being able to use
Bochs IDB Mode in particular with these kinds of code enables casual decoding
of strings and unpacking/dumping of payloads without having to address concerns
such as anti-reverse engineering, subprocess debugging, etc.

## About Function Replacements
The file `function_replacements.c` contains compact C implementations of
several functions associated with simple string decoding and malware unpacking
routines. It is provided for reference.

After compiling `function_replacements.c`, the relevant function opcodes were
extracted using `emit_fnbytes_python()` from `mykutils.py` (located under
`/python/flare` in the flare-ida repository). The opcodes were then added as
Python strings to a library of function implementations in `code_grafter.py`
(also in `/python/flare`).
