from getsympos import core
from elftools.elf.elffile import ELFFile
from tabulate import tabulate

import argparse
import logging


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--elf", type=str, required=True, help="Path to the debug info file.")
    # FIXME: memory consumption is huge when we don't specify a CU
    parser.add_argument("--cu", type=str, required=False, help="Compilation unit to filter the debug information.")
    parser.add_argument("--symbols", nargs="*", required=False, help="Symbol name to analyze.")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,  # or DEBUG for more detail
        format="%(levelname)s: %(message)s"
    )

    with open(args.elf, "rb") as f:
        elf = ELFFile(f)
        data = core.analyze_elf(elf, args.symbols, args.cu)
        elf.close()

    if data:
        header = ["Symbol", "File", "Line", "Address", "Sympos"]
        print(tabulate(data, headers=header, tablefmt="simple"))
    else:
        print("No symbols found")
