# FLARE Team Reversing Repository #
This repository contains a collection of IDA Pro scripts and plugins used by the FireEye Labs Advanced Reverse Engineering (FLARE) team.

## plugins ##

To install, copy the contents of the plugins directory in this repository to your %PROGRAMFILES%\IDA\plugins folder. 

## python ##
The python directory here can be copied to your %PROGRAMFILES%\IDA\python folder, or you can modify your PYTHONPATH environment variable to include the directory.

## Provided Plugins ##

### Shellcode Hashes  ###
The shellcode_hashes_search_plugin.py IDA plugin implements the hash searching described here: https://www.mandiant.com/blog/precalculated-string-hashes-reverse-engineering-shellcode/.

The shellcode_hashes directory contains the script used to create the database for the shellcode_hash_search.py script, along with a provided database.

### Struct Typer ###
The struct_typer_plugin.py plugin implements the struct typing described here: https://www.mandiant.com/blog/applying-function-types-structure-fields-ida/


### StackStrings ###
The stackstrings_plugin.py implements the recovery of manually constructed strings described here: http://www.fireeye.com/blog/threat-research/2014/08/flare-ida-pro-script-series-automatic-recovery-of-constructed-strings-in-malware.html

### MSDN Annotations ###
This script for IDA Pro adds MSDN information from a XML file to the database. Information about this plugin can be found at: https://www.fireeye.com/blog/threat-research/2014/09/flare-ida-pro-script-series-msdn-annotations-ida-pro-for-malware-analysis.html

The following functionality is included:

  - Backup the original database
  - Retrieve all imported functions
  - Import function descriptions
  - Import argument descriptions
  - Create custom enumerations for identified constants including descriptions
  - Rename constants to their readable values

#### MSDN Annotations Usage ####

TL;DR: In IDA run *annotate_IDB_MSDN.py*.

All files (IDAPython scripts, XML parser, MSDN information XML file, etc.) 
should be located in the same directory accessible by IDA Pro.
In IDA use *File - Script file...* (ALT + F7) to open **annotate_IDB_MSDN.py**.
The form will allow you to change the settings and annotate the IDB file after
you click OK.

After executing the script once, *View - Recent scripts* (ALT + F9) can be used
as well.

### ApplyCalleeType ###
This plugin allows you to specify or choose a function type for indirect calls as described here: https://www.fireeye.com/blog/threat-research/2015/04/flare_ida_pro_script.html


### idb2pat ###
This script allows you to easily generate function patterns from an existing IDB database that can then be turned into FLIRT signatures to help identify similar functions in new files. More information is available at:
https://www.fireeye.com/blog/threat-research/2015/01/flare_ida_pro_script.html


### argtracker ###
This utility can help you identify static arguments to functions used within a program. This is most commonly used to extract arguments to string decoder functions. Example usage is available in 

* examples/argtracker_example1.py
* examples/argtracker_example2.py

A blog post with further information is available at:

https://www.fireeye.com/blog/threat-research/2015/11/flare_ida_pro_script.html

### objc2_analyzer ###
This script creates cross-references between selector references and their implementations as defined in the Objective-C  runtime related sections of the target Mach-O executable. It also patches selector reference pointers to instead point to their implementation function. This makes analysis of Objective-C code easier by enabling smooth transitions between an implementation and the locations where its selector is referenced throughout the code. Helpful Objective-C code comments are added to each call to objc_msgSend variants to clearly indicate which method is being called on which class.


### ironstrings ###
`ironstrings.py` is an IDAPython script that uses code emulation to recover constructed strings (stackstrings) from malware. Please see the details in the script's [README](https://github.com/fireeye/flare-ida/blob/master/python/flare/ironstrings/README.md).

### Code Grafter ###
`code_grafter.py` is an IDAPython script that grafts code to an IDA database to implement various imported functions and increase the likelihood of being able to execute an unpacker or decoder entirely under Bochs (or any other emulation tools that don't implement special handling for these functions). This prevents faults when emulated execution reaches functions such as `VirtualAlloc` or `lstrlenA`.
