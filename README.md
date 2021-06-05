Nvidia SAI implementation
============================

This repository contains SAI implementation for Nvidia hardware

SAI headers are based on latest head (as of Apr 5, 2021) of branch v1.8 (release v1.8.1) SAI headers can be 
downloaded from https://github.com/opencomputeproject/SAI/

The implementation is written over Nvidia SDK API. The API and documentation for it, are available in
https://github.com/Mellanox/SwitchRouterSDK-interfaces

Compilation is done with the flag USE_SAI_INTERFACE=1
For example : make all_native USE_KERNEL=0 USE_SAI_INTERFACE=1
The output result is SAI library, called libsai.

User applications can then link with this library, in order to use the SAI implementation.
