# GetSympos

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
