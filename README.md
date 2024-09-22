# gdb_auto_memory

A helper script for IDA Remote GDB Debugger (gdbserver) to automatically setup memory region.

This script use gdbserver's host io function (vFile:pread) to read /proc/XXX/maps and then insert the regions just like IDA debug server.

## Usage

Run gdb_auto_memory.py when you start debugging.

You can run it multiple times if you think there's new module loaded. The script will only handle newly appeared regions, and can correctly handle process restarts meanwhile.