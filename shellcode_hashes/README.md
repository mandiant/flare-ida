# shellcode_hashes #

make_sc_hash_db.py is the script used to generate a SQLite database of function name hashes for use with the shellcode_hashes_search_plugin.py IDA script.

Run the script as:

'''python make_sc_hash_db.py <database_name> <dll_directory>'''

where <database_name> is the output database name to create, and <dll_directory> is a directory containing the DLLs you want to include. An initial database of interesting Microsoft DLLs is included here named sc_hashes.db.
