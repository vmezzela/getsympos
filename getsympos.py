#!/usr/bin/python3

from io import UnsupportedOperation
from elftools.dwarf.compileunit import CompileUnit
from elftools.dwarf.die import DIE
from elftools.dwarf.locationlists import LocationParser, LocationExpr
from elftools.dwarf.dwarf_expr import DWARFExprParser
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from functools import wraps
from pathlib import PurePath
from tabulate import tabulate

import argparse
import logging

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
    Decode and return the name of a symbol from its DWARF attribute.

    Args:
        attr_name: The attribute containing the symbol name.

    Returns:
        str: The decoded symbol name.
    """
    return attr_name.value.decode('utf-8', errors='ignore')


@require_attr("DW_AT_decl_file", require_die=True)
def desc_file(attr_name, die):
    """
    Retrieve and return the file path where a symbol is defined.

    Args:
        attr_name: The attribute containing the file index.
        die (DIE): The Debugging Information Entry associated with the symbol.

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
    Retrieve and return the line number where a symbol is defined.

    Args:
        attr_name: The attribute containing the line number.

    Returns:
        int: The line number.
    """
    return attr_name.value

@require_attr("DW_AT_low_pc")
def desc_addr(attr_name):
    """
    Retrieve and return the address of the symbol.

    Args:
        attr_name: The attribute containing the address.

    Returns:
        int: The address.
    """
    return attr_name.value


@require_attr("DW_AT_location", require_die=True)
def desc_location(attr_name, die):
    """
    Retrieve and return the location/address of a variable from DW_AT_location.

    Args:
        attr_name: The attribute containing the address.

    Returns:
        int: The address.
    """
    cu = die.cu
    dwarfinfo = cu.dwarfinfo

    loclists = dwarfinfo.location_lists()
    locparser = LocationParser(loclists)

    loclist = locparser.parse_from_attribute(attr_name, cu.header.version, die)
    if isinstance(loclist, LocationExpr):
        exprparser = DWARFExprParser(cu.structs)
        parsed = exprparser.parse_expr(loclist.loc_expr)
        for op in parsed:
            if op.op_name == "DW_OP_addr":
                return op.args[0]

    logging.error("location parsing not yet implemented for non LocationExpr type")


FUNC_ATTR_DESCRIPTIONS = dict(
    DW_AT_name=desc_name,
    DW_AT_decl_file=desc_file,
    DW_AT_decl_line=desc_line,
    DW_AT_low_pc=desc_addr,
    DW_AT_location=desc_location
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


def die_is_variable(die: DIE):
    """
    Check if a DIE represents a variable.

    Args:
        die (DIE): The Debugging Information Entry to check.

    Returns:
        bool: True if the DIE is a variable, False otherwise.
    """
    return die.tag == 'DW_TAG_variable'


def get_symtab_sympos(symbol, address):
    """
    Retrieve the relative symbol position of a given symbol identified by its
    name and its address. The address is needed because more symbols with the
    same name might be present in the symbol table.

    Args:
        symbol: The name of the symbol.
        address: The address of the symbol.
    """
    symtab = elf.get_section_by_name(".symtab")
    assert isinstance(symtab, SymbolTableSection)

    matches = 0
    for sym in symtab.iter_symbols():
        sym_type = sym['st_info']['type']

        # Skip entries that are not functions or variables
        if sym_type != 'STT_FUNC' and sym_type != 'STT_OBJECT':
            continue

        sym_addr = sym['st_value']
        if sym.name == symbol:
            matches += 1
            if sym_addr == address:
                return matches

    logging.error("Couldn't find sympos for %s", symbol)
    return matches


def get_die_information(die: DIE, filter=""):
    """
    Extract and print symbol details including its name, file, and line number.

    Args:
        die (DIE): The Debugging Information Entry for a symbol.
    """
    if die_is_func(die):
        addr_tag = "DW_AT_low_pc"
    elif die_is_variable(die):
        addr_tag = "DW_AT_location"
    else:
        return []

    name = FUNC_ATTR_DESCRIPTIONS["DW_AT_name"](die)
    if filter and name != filter:
        return []

    file = FUNC_ATTR_DESCRIPTIONS["DW_AT_decl_file"](die)
    line = FUNC_ATTR_DESCRIPTIONS["DW_AT_decl_line"](die)
    addr = FUNC_ATTR_DESCRIPTIONS[addr_tag](die)

    if name and file and line and addr:
        file = clean_relative_path(file)
        sympos = get_symtab_sympos(name, addr)
        return [name, file, line, hex(addr), sympos]

    if filter:
        # Only emit this when filter is enabled
        logging.error("Couldn't find necessary attrybutes for %s", name)

    return []


def desc_cu(cu: CompileUnit, filter_cu_name="", filter_die_name=""):
    """
    Extract and print information about a Compilation Unit (CU) and its symbols.

    Args:
        cu (CompileUnit): The Compilation Unit to analyze.
    """
    cu_die = cu.get_top_DIE()
    name_attr = cu_die.attributes.get('DW_AT_name')
    if not name_attr:
        return []

    name = PurePath(name_attr.value.decode('utf-8', errors='ignore'))
    name = clean_relative_path(name)
    if filter_cu_name and name != PurePath(filter_cu_name):
        return []

    logging.debug(f"\n[Compilation Unit] Offset: {cu.cu_offset}, Name: {name}")

    return [
        func_info
        for die in cu.iter_DIEs()
        if (func_info := get_die_information(die, filter_die_name))
    ]


def main():
    global elf
    parser = argparse.ArgumentParser()
    parser.add_argument("--elf", type=str, required=True, help="Path to the debug info file.")
    # FIXME: memory consumption is huge when we don't specify a CU
    parser.add_argument("--cu", type=str, required=False, help="Compilation unit to filter the debug information.")
    parser.add_argument("--symbol", type=str, required=False, help="Symbol name to analyze.")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,  # or DEBUG for more detail
        format="%(levelname)s: %(message)s"
    )

    data = []
    with open(args.elf, "rb") as f:
        elf = ELFFile(f)

        if not elf.has_dwarf_info():
            logging.error("Debug info missing in ELF file")
            return 1

        dwarf_info = elf.get_dwarf_info(relocate_dwarf_sections=False)

        logging.info("Starting sympos analysis")
        for cu in dwarf_info.iter_CUs():
            cu_info = desc_cu(cu, filter_cu_name=args.cu, filter_die_name=args.symbol)
            data.extend(cu_info)
        logging.info("Sympos analysis finished")

        elf.close()

    if data:
        header = ["Symbol", "File", "Line", "Address", "Sympos"]
        print(tabulate(data, headers=header, tablefmt="simple"))
    else:
        print("No symbols found")
