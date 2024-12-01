
import os
import struct
from collections import defaultdict


def parse_maps(pid):
    maps = []
    with open(f"/proc/{pid}/maps", "r") as f:
        for line in f:
            parts = line.split()
            addr_range = parts[0].split("-")
            start, end = int(addr_range[0], 16), int(addr_range[1], 16)
            maps.append((start, end))
    return maps


def parse_pagemap(pid, vaddr):
    page_size = os.sysconf("SC_PAGE_SIZE")
    pagemap_offset = (vaddr // page_size) * 8
    with open(f"/proc/{pid}/pagemap", "rb") as f:
        f.seek(pagemap_offset)
        entry = f.read(8)
        if not entry:
            return None
        entry = struct.unpack("Q", entry)[0]
        if entry & (1 << 63):  # Проверяем флаг присутствия
            pfn = entry & ((1 << 55) - 1)
            return pfn * page_size
    return None


def build_page_table(pid, maps):
    page_table = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))

    for start, end in maps:
        for vaddr in range(start, end, os.sysconf("SC_PAGE_SIZE")):
            paddr = parse_pagemap(pid, vaddr)
            if paddr is not None:
                pgd = (vaddr >> 39) & 0x1FF
                p4d = (vaddr >> 30) & 0x1FF
                pud = (vaddr >> 21) & 0x1FF
                pmd = (vaddr >> 12) & 0x1FF
                page_table[pgd][p4d][pud].append((pmd, vaddr, paddr))

    return page_table


def paginate_output(output, page_size=20):
    """Выводит текст постранично."""
    for i in range(0, len(output), page_size):
        #os.system("clear")  # Очистка консоли для удобства
        print("\n".join(output[i:i + page_size]))
        if i + page_size < len(output):
            input("Press Enter to continue...")


def display_page_table(page_table):
    output = []
    for pgd, p4ds in page_table.items():
        output.append(f"PGD {hex(pgd)}")
        for p4d, puds in p4ds.items():
            output.append(f"  P4D {hex(p4d)}")
            for pud, pmds in puds.items():
                output.append(f"    PUD {hex(pud)}")
                for pmd, vaddr, paddr in pmds:
                    output.append(f"      PMD {hex(pmd)} -> VA: {hex(vaddr)}, PA: {hex(paddr)}")

    paginate_output(output)


if __name__ == "__main__":
    pid = input("Enter the PID of the process: ")
    try:
        maps = parse_maps(pid)
        page_table = build_page_table(pid, maps)
        display_page_table(page_table)
    except PermissionError:
        print("Permission denied. Try running the script as root.")
    except FileNotFoundError:
        print(f"Process with PID {pid} not found.")