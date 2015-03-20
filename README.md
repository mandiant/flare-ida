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
The stackstrings_plugin.py implements the recovery of manually constructed strings described here: http://www.fireeye.com/blog/technical/malware-research/2014/08/flare-ida-pro-script-series-automatic-recovery-of-constructed-strings-in-malware.html

### MSDN Annotations ###
This script for IDA Pro adds MSDN information from a XML file to the database.
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

### MSDN Annotations Requirements ####

Download and install an offline version of the MSDN documentationYou can download the Microsoft Windows SDK MSDN documentation. The standalone installer can be downloaded from http://www.microsoft.com/en-us/download/details.aspx?id=18950. Installation is described here: https://www.fireeye.com/blog/threat-research/2014/09/flare-ida-pro-script-series-msdn-annotations-ida-pro-for-malware-analysis.html

