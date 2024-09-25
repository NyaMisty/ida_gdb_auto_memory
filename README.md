# gdb_auto_memory

A helper script for IDA Remote GDB Debugger (gdbserver) to automatically setup memory region.

This script use gdbserver's host io function (vFile:pread) to read /proc/XXX/maps and then insert the regions just like IDA debug server.

## Usage

- Method 1: Run gdb_auto_memory.py using Alt-F7 when you start debugging. You can run it multiple times if you think there's new module loaded. The script will only handle newly appeared regions, and can correctly handle process restarts meanwhile.

- Method 2: Install it into plugins, and press Ctrl-Alt-G to enable the plugin (just need once for each idb, after that plugin will automatically load each time)
    - The plugin will automatically refresh module list when process was suspended (except single step).
    - If plugin fails to auto-reload the module list, you can forcely trigger a refresh by right-click in `Modules list` view (`Debugger -> Debugger windows -> Module list`)
