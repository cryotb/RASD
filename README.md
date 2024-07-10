# RASD
Parts of this project have been reverse engineered and reconstructed from R5AC, an in-house anticheat solution currently deployed in APEX LEGENDS. I have simplified some of their checks due to time constrains, but behavior should be identical. I have written a few rather small tests to confirm this, which execute a function monitored by a replicated R5AC stackwalk, which intentionally do following things:
- call into monitored function from legitimate place (e.g from within the main executable)
- call into monitored function from code residing in a manually allocated RWX page.
- call into monitored function with 2 open-source return address spoofers. (gadgets used: jmp, add rsp; ret)
# How does it work?
Currently they use an API for generating a backtrace recording. It's located in `kernel32.dll` and named `RtlCaptureStackBackTrace`.
These checks are riddled around the game's normal code and you will eventually call into them. 

If your cheat generates a CALL instruction on anything that later on may land into a stackwalk check, your cheat module may be exposed because by generating aforementioned CALL, you are pushing a return address to the stack which will obviously point to your cheat if you want it to return normally. There are ways to overcome this, but this isn't a bypass repository.

You should always keep in mind that it's not hard for an anticheat to detect an anomaly here, if you add the fact that all of this comes from a module that isn't even in LDR nor signed/in a whitelist, then you definitely know something's up.

# What's interesting about it?
Currently, they use following logic for what i assume, is for detecting gadgets commonly used for this purpose:

```
  if( !tools::retaddr_is_call_insn(retaddr) )
            {
                // IF THIS RETURN ADDRESS HAS NOT BEEN GENERATED BY A CALL INSTRUCTION,
                //  PERFORM ADDITIONAL ANALYSIS TO DETERMINE IF A RETURN ADDRESS SPOOFER WAS POTENTIALLY USED.
                DWORD_PTR v50 = BASE_OF(retaddr);
                DWORD_PTR v57 = 2i64;
                while (*(BYTE*)(v50 - v57) != 0xFF || (((*(BYTE*)(v50 - v57 + 1) & 0x38) - 16) & 0xF7) != 0) // <------------------------------- see here
                {
                    if (++v57 > 7)
                    {
                        printf("[FLAG//////RETADDR SPOOFER] suspicious record at %i (%p)\n", i, retaddr);
                        break;
                    }
                }
            }
```
They seem to use this generic algorithm for detecting a range of gadgets. Further analysis is to be done on it.

# Which gadgets does it detect?
It pretty much detects certain variations of gadgets commonly used when doing anything with return address spoofing, i have included 2 open-source projects to demonstrate the detection:
1. https://www.unknowncheats.me/forum/anti-cheat-bypass/268039-x64-return-address-spoofing-source-explanation.html
2. https://www.unknowncheats.me/forum/anti-cheat-bypass/512002-x64-return-address-spoofing.html

All credits for these go to the corresponding authors. They are just being shipped for demonstration purposes.

