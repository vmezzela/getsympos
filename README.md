# GetSympos

When livepatching a function with a non-unique name in an ELF binary, you need
the symbol position (sympos) to distinguish between the different instances.

`getsympos` is a utility that retrieves this sympos for you.

## Usage

```sh
getsympos --elf <elf> --function <function> --cu <src file with the function definition>

# if the elf doesn't have the debug symbols:
export DEBUGINFOD_URLS="<URL>:<PORT>" # Optional
getsympos --elf $(debuginfod-find debuginfo <elf>) 
```

## Installation

```
pipx install .
```
