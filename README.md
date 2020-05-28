# Ghidra Revsync Plugin

# revsync

Revsync is a realtime syncing plugin for IDA Pro, Binary Ninja, and now Ghidra!

The Revsync Ghidra plugin is compatible with the original [Revsync IDA Pro and Binary Ninja plugin](https://github.com/lunixbochs/revsync).

The Ghidra plugin currently only syncs:
 - Comments
 - Symbol names

Future versions may expand to include the stack variable names, structs, and code coverage modules that the original revsync supports. Right now any sync messages for these are logged to the console but not committed.

# Installation

See [Installation.md](Installation.md) for installation directions.

# Download

[Download latest](https://github.com/williamshowalter/revsync_ghidra/releases)

# Requirements / Notices
- Requires Ghidra 9.1.2. 
- Has only been tested on Linux so far.
- Config file must be in ~/.revsync/config.json (see [Installation.md](Installation.md))
- Syncing is based on SHA256 hash of the executable, which wasn't present in the program information on older versions of Ghidra before October 2019. If a program was imported with an older version but the project was later upgraded, it won't have the SHA256 hash and will need to be imported again.