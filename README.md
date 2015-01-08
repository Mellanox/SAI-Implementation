Mellanox SAI implementation
============================

This repository contains SAI implementation for Mellanox hardware.

SAI headers are based on release v0.9.0, with few fixes. SAI headers can be downloaded from 
https://github.com/opencomputeproject/OCP-Networking-Project-Community-Contributions

The implementation is written over Mellanox SwitchX interfaces API. The API and documentation for it, are available in
https://github.com/Mellanox/SwitchX-interfaces

Compilation is done with the flag USE_SAI_INTERFACE=1.
For example : make all_native USE_KERNEL=0 USE_SAI_INTERFACE=1
The output result is SAI library, called libsai.

User applications can then link with this library and sxapi library, in order to use the SAI implementation.
