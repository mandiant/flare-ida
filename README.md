# Mandiant Reversing Repository #
This repository contains a collection of IDA Pro scripts and plugins.

## plugins ##

To install, copy the contents of the plugins directory in this repository to your %PROGRAMFILES%\IDA\plugins folder. 

## python ##
The python directory here can be copied to your %PROGRAMFILES%\IDA\python folder, or you can modify your PYTHONPATH environment variable to include the directory.

## Provided Plugins ##

### Shellcode Hashes  ###
The shellcode_hashes_search_plugin.py IDA plugin implements the hash searching described here https://www.mandiant.com/blog/precalculated-string-hashes-reverse-engineering-shellcode/.

The shellcode_hashes directory contains the script used to create the database for the shellcode_hash_search.py script, along with a provided database.

### Struct Typer ###
The struct_typer_plugin.py plugin implements the struct typing described here https://www.mandiant.com/blog/applying-function-types-structure-fields-ida/


