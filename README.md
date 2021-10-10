#AlphaGolang 
by Juan Andres Guerrero-Saade (JAG-S @ SentinelLabs)

###Description: 
AlphaGolang is a collection of IDAPython scripts to help malware reverse engineers master Go binaries. The idea is to break the scripts into concrete steps, thus avoiding brittle monolithic scripts, and mimicking the methodology an analyst might follow when tackling a Go binary.

Scripts are released under GPL license (honoring Tim Strazzere's original Golang Loader Assist which we refactored and updated for python3, props to Tim :) ). Contributions are welcome and encouraged!

###Requirements: IDA Pro (ideally v7.6+) and Python3 (ew).
The first two steps (recreate_pclntab and function_discovery_and_renaming) will work on IDA v7.5- but scripts beyond that require IDAv7.6+. Newer versions are the ideal target for newer scripts going forward.

**Original Reference:** Mandiant Cyber Defense Summit 2021 (Video Pending)

---
Current Components:
---

- Step 1 (IDA v7.5- compatible)
> recreate_pclntab.py  (READY)
        |_> Recreates the gopclntab section from heuristics
        |_> Bruteforce discovers new functions based on the pcln table
        |_> Mostly useful for IDA v7.5-

-Step 2 (IDA v7.5- compatible)
> function_renaming.py (READY)
        |_> Split from golang loader assist
        |_> Fixed some function name cleaning issues of python3

-Step 3 (IDA v7.6+)
> categorize_go_folders.py (READY)

-Step 4 (IDA v7.6+)
> fix_string_cast.py (READY)
        |_> Split from golang loader assist
        |_> New sanity checks make it far more effective

---
Pending fixes and room for contributions:
  X More string load heuristics

Next steps:
  X generate_pseudocode.py 
  X user_code_auto_yara_gen.py
  X user_string_ref_tracking.py
  X Automatically set breakpoints for dynamic analysis of arguments
---

###Credit to:
- Tim Strazzere for releasing the original golang_loader_assist
- Milan Bohacek (Avast Software s.r.o.) for his invaluable help figuring out the idatree API.
- Joakim Kennedy (Intezer)
- Ivan Kwiatkowski (Kaspersky GReAT)
