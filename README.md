# Repdriver-v2

A upgrade windows driver from v1 that use ioctl, now its using registry and with a rich features

## Goals
- Core hooking logic remains flexible, allowing future transport layers (e.g., ALPC, named pipes) to be swapped in with minimal code changes
- Designed to bypass modern kernel-level protections (ETW, callback hooks, PatchGuard) by leveraging registry callbacks as the trigger mechanism

## Features (WIP)
- Attach to processes by name
- Hide processes from system visibility
- Force terminate processes
- Protect processes from termination (anti-kill)
- Retrieve base and module addresses of processes
- Load vulnerable drivers via custom mapper for stealthy module injection (vulnerable drivers?)
- Read Process memory with string supported
- Write Process memory
- Scan process memory for patterns or signatures
- Advanced stealth features: inline hooking, SSDT/IDT manipulation, and callback interception
- Registry-based command queue with encrypted payloads for secure communication
- Encrypted HTTP/HTTPS callbacks for command retrieval
- C2 communication support with configurable beacon intervals
- DNS-based tunneling fallback channel
- Peer-to-peer C2 mesh networking for resilience
- In-memory staging of payloads to avoid disk writes
- Persistence mechanisms via registry auto-run values and service creation
- Dynamic sleep/jitter scheduling to evade sandbox detection

### 
This Project is inspired by the `GsDriver`. you can check the base in https://github.com/781732825/GsDriver