#!/usr/bin/python3

from elftools.dwarf.compileunit import CompileUnit
from elftools.dwarf.die import DIE
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from functools import wraps
from libdebuginfod import DebugInfoD
from pathlib import Path, PurePath
from tabulate import tabulate

import argparse
import logging
import os
import shutil

def require_attr(attr, require_die=False):
    def decorator(func):
        @wraps(func)
        def wrapper(die: DIE):
            attr_value = die.attributes.get(attr)
            if attr_value:
                return func(attr_value, die) if require_die else func(attr_value)
            return None
        return wrapper
    return decorator


def clean_relative_path(path: PurePath):
    """
    Drop all the leading ".." from the path

    Args:
        path: The path to clean.

    Returns:
        PurePath: The cleaned path.
    """
    parts = path.parts
    if parts and parts[0] != "..":
        return path

    new_path = PurePath(*parts[1:])
    return clean_relative_path(new_path)


@require_attr("DW_AT_name")
def desc_name(attr_name):
    """
    Decode and return the name of a function from its DWARF attribute.

    Args:
        attr_name: The attribute containing the function name.

    Returns:
        str: The decoded function name.
    """
    return attr_name.value.decode('utf-8', errors='ignore')


@require_attr("DW_AT_decl_file", require_die=True)
def desc_file(attr_name, die):
    """
    Retrieve and return the file path where a function is defined.

    Args:
        attr_name: The attribute containing the file index.
        die (DIE): The Debugging Information Entry associated with the function.

    Returns:
        str: The full file path (directory + file name).
    """
    cu = die.cu
    dwarfinfo = cu.dwarfinfo
    lineprogram = dwarfinfo.line_program_for_CU(cu)

    # Filename/dirname arrays are 0-based in DWARF v5
    offset = 0 if lineprogram.header.version >= 5 else -1

    file_index = offset + int(attr_name.value)
    assert 0 <= file_index < len(lineprogram.header.file_entry)
    file_entry = lineprogram.header.file_entry[file_index]
    file_name = PurePath(file_entry.name.decode('utf-8', errors='ignore'))

    dir_index = offset + int(file_entry.dir_index)
    assert 0 <= dir_index < len(lineprogram.header.include_directory)
    enc_dir_path = lineprogram.header.include_directory[dir_index]
    dir_path = PurePath(enc_dir_path.decode('utf-8', errors='ignore'))

    return dir_path/file_name


@require_attr("DW_AT_decl_line")
def desc_line(attr_name):
    """
    Retrieve and return the line number where a function is defined.

    Args:
        attr_name: The attribute containing the line number.

    Returns:
        int: The line number.
    """
    return attr_name.value

@require_attr("DW_AT_low_pc")
def desc_addr(attr_name):
    """
    Retrieve and return the address of the function.

    Args:
        attr_name: The attribute containing the address.

    Returns:
        int: The address.
    """
    return attr_name.value


FUNC_ATTR_DESCRIPTIONS = dict(
    DW_AT_name=desc_name,
    DW_AT_decl_file=desc_file,
    DW_AT_decl_line=desc_line,
    DW_AT_low_pc=desc_addr
)


def die_is_func(die: DIE):
    """
    Check if a DIE represents a function (subprogram).

    Args:
        die (DIE): The Debugging Information Entry to check.

    Returns:
        bool: True if the DIE is a function, False otherwise.
    """
    return die.tag == 'DW_TAG_subprogram'


def get_function_symtab_sympos(function, address):
    """
    Retrieve the relative symbol position of a given function identified by its
    name and its address. The address is needed because more function with the
    same name might be present in the symbol table.

    Args:
        function: The name of the function.
        address: The address of the function.
    """
    symtab = elf.get_section_by_name(".symtab")
    assert isinstance(symtab, SymbolTableSection)

    matches = 0
    for sym in symtab.iter_symbols():
        sym_type = sym['st_info']['type']

        # Skip entries that are not functions
        if sym_type != 'STT_FUNC':
            continue

        sym_addr = sym['st_value']
        if sym.name == function:
            matches += 1
            if sym_addr == address:
                return matches

    return matches


def get_function_information(die: DIE, filter_function_name=""):
    """
    Extract and print function details including its name, file, and line number.

    Args:
        die (DIE): The Debugging Information Entry for a function.
    """
    assert die_is_func(die)

    name = FUNC_ATTR_DESCRIPTIONS["DW_AT_name"](die)
    if filter_function_name and name != filter_function_name:
        return

    file = FUNC_ATTR_DESCRIPTIONS["DW_AT_decl_file"](die)
    line = FUNC_ATTR_DESCRIPTIONS["DW_AT_decl_line"](die)
    addr = FUNC_ATTR_DESCRIPTIONS["DW_AT_low_pc"](die)

    if name and file and line and addr:
        file = clean_relative_path(file)
        sympos = get_function_symtab_sympos(name, addr)
        return [name, file, line, hex(addr), sympos]

    return []


def desc_cu(cu: CompileUnit, filter_cu_name="", filter_function_name=""):
    """
    Extract and print information about a Compilation Unit (CU) and its functions.

    Args:
        cu (CompileUnit): The Compilation Unit to analyze.
    """
    cu_die = cu.get_top_DIE()
    name_attr = cu_die.attributes.get('DW_AT_name')
    if not name_attr:
        return

    name = PurePath(name_attr.value.decode('utf-8', errors='ignore'))
    name = clean_relative_path(name)
    if filter_cu_name and name != PurePath(filter_cu_name):
        return

    logging.debug(f"\n[Compilation Unit] Offset: {cu.cu_offset}, Name: {name}")

    return [
        func_info
        for die in cu.iter_DIEs()
        if die_is_func(die)
        if (func_info := get_function_information(die, filter_function_name))
    ]


def get_build_id(elf):
    notes_section = elf.get_section_by_name(".notes")
    buildid_section = elf.get_section_by_name(".note.gnu.build-id")

    if notes_section and buildid_section:
        raise RuntimeError("Both .notes and .note.gnu.build-id exist, expected only one.")

    section = notes_section or buildid_section
    for note in section.iter_notes():
        if note is None:
            continue
        if note["n_type"] == "NT_GNU_BUILD_ID" and note["n_name"] == "GNU":
            return note["n_desc"]

    return None


def main():
    global elf
    parser = argparse.ArgumentParser()
    parser.add_argument("--elf", type=str, required=True, help="Path to the debug info file.")
    # FIXME: memory consumption is huge when we don't specify a CU
    parser.add_argument("--cu", type=str, required=False, help="Compilation unit to filter the debug information.")
    parser.add_argument("--function", type=str, required=False, help="Function name to analyze.")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,  # or DEBUG for more detail
        format="%(levelname)s: %(message)s"
    )

    f = open(args.elf, "rb")
    elf = ELFFile(f)

    if not elf.has_dwarf_info():
        logging.warning("Debug info missing")
        logging.info(f'Downloading debug info from {os.environ.get("DEBUGINFOD_URLS")}')
        build_id = get_build_id(elf)
        assert build_id, f"Coulnd't find build id for {args.elf}"

        with DebugInfoD() as d:
            _, path = d.find_debuginfo(build_id)

            # It happens sometimes that debuginfod can't find the debuginfo
            # because the environment variable DEBUGINFOD_URLS is not set
            # and it stores an empty cache file. If we then add the server
            # url but the empty cache file is still present, debuginfo
            # doesn't query the remote server to fetch the updated
            # debuginfo and just returns the empty one from the cache.
            # Hence workaround this issue by trying to delete the file and
            # query debuginfod again.
            if not path:
                logging.warning(f"Coulnd't find debug info for {args.elf}:{build_id}, trying do clear the cache.")
                cache_dir = Path.home()/".cache"/"debuginfod_client"/build_id
                assert cache_dir.exists()
                shutil.rmtree(cache_dir)
                logging.info(f"Removed cached directory: {cache_dir}")

                logging.info(f'Downloading (again) debug info from {os.environ.get("DEBUGINFOD_URLS")}')
                _, path = d.find_debuginfo(build_id)

        assert path, f"Coulnd't find debug info for {args.elf}:{build_id}"
        logging.info("Debug info downloaded!")

        # Replace the elf with the new one
        f.close()
        elf.close()
        f = open(path, "rb")
        elf = ELFFile(f)
    else:
        logging.info("Found debug info")


    assert elf.has_dwarf_info()
    dwarf_info = elf.get_dwarf_info(relocate_dwarf_sections=False)

    logging.info("Starting sympos analysis")

    data = []
    for cu in dwarf_info.iter_CUs():
        cu_info = desc_cu(cu, filter_cu_name=args.cu, filter_function_name=args.function)
        if cu_info:
            data.extend(cu_info)

    elf.close()
    f.close();

    if data:
        header = ["Function", "File", "Line", "Address", "Sympos"]
        print(tabulate(data, headers=header, tablefmt="simple"))
    else:
        print("No symbols found")
