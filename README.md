Mellanox SAI implementation
============================

This repository contains SAI implementation for Mellanox hardware

SAI headers are based on latest head (as of Oct 30, 2020) of branch v1.6 (release v1.6.6) SAI headers can be 
downloaded from https://github.com/opencomputeproject/SAI/

The implementation is written over Mellanox SDK API. The API and documentation for it, are available in
https://github.com/Mellanox/SwitchRouterSDK-interfaces

Compilation is done with the flag USE_SAI_INTERFACE=1
For example : make all_native USE_KERNEL=0 USE_SAI_INTERFACE=1
The output result is SAI library, called libsai.

User applications can then link with this library, in order to use the SAI implementation.
