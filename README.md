Mellanox SAI implementation
============================

This repository contains SAI implementation for Mellanox hardware.

SAI headers are based on latest head (as of Apr 7, 2016) of release v0.9.3.
In addition, it includes pull request https://github.com/opencomputeproject/SAI/pull/72
which changes the add/remove ports to VLAN to VLAN member object.
The current API compiles with SONIC.

SAI headers can be downloaded from https://github.com/opencomputeproject/SAI/

The implementation is written over Mellanox SwitchX interfaces API. The API and documentation for it, are available in
https://github.com/Mellanox/SwitchX-interfaces

Compilation is done with the flag USE_SAI_INTERFACE=1.
For example : make all_native USE_KERNEL=0 USE_SAI_INTERFACE=1
The output result is SAI library, called libsai.

User applications can then link with this library, in order to use the SAI implementation.

Compilation instructions to create deb package for Sonic :
debuild -e make_extra_flags="DEFS=-DACS_OS" -us -uc -d -b 