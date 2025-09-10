# GetSympos

When livepatching a function with a non-unique name in an ELF binary, you need
the symbol position (sympos) to distinguish between the different instances.

`getsympos` is a utility that retrieves this sympos for you.

The livepatch symbol has sympos=0 only when the the symbol name of the target
is unique, otherwise the sympos is counted starting from 1.

## Usage

```sh
getsympos --elf <elf> --function <function> --cu <src file with the function definition>

# if the elf doesn't have the debug symbols:
export DEBUGINFOD_URLS="<URL>:<PORT>" # Optional
getsympos --elf $(debuginfod-find debuginfo <elf>) 
```

> Sometimes the debuginfod query fails, clearing the cache might solve the
> issue

## Installation

```
pipx install .
```
