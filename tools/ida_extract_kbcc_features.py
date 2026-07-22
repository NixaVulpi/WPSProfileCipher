"""
Extract KBaseConfigCenter feature descriptors from an open IDA database.

Run with File -> Script file... while kbaseconfigcenter[64].dll is open.
The script intentionally uses structural validation instead of fixed RVAs.
"""

from __future__ import annotations

import csv
import json
import os
from dataclasses import asdict, dataclass

import ida_bytes
import ida_idaapi
import ida_kernwin
import ida_segment
import idautils
import idc


GROUPS = {"default", "support", "enable", "filter", "value"}
TYPE_NAMES = {0: "bool", 1: "int", 2: "string"}
MAX_STRING = 512


@dataclass(frozen=True)
class Field:
    name: str
    value_type: int


@dataclass(frozen=True)
class Descriptor:
    address: str
    group: str
    name: str
    fields_address: str
    fields_count: int
    fields: tuple[Field, ...]


def segment_for(ea: int):
    return ida_segment.getseg(ea) if ea not in (0, ida_idaapi.BADADDR) else None


def read_ascii(ea: int) -> str | None:
    if segment_for(ea) is None:
        return None
    # A positive length makes IDA read past the terminating NUL.  These DLLs
    # pack many descriptor strings together, so let IDA determine the C-string
    # boundary first (for example, ConfidentialityLevelKeyWord is immediately
    # followed by StartMenuLinkSet in this build).
    raw = idc.get_strlit_contents(ea, -1, idc.STRTYPE_C)
    if raw is None:
        raw = ida_bytes.get_bytes(ea, MAX_STRING)
        if raw is not None:
            raw = raw.split(b"\0", 1)[0]
    if not raw:
        return None
    try:
        value = raw.decode("ascii")
    except UnicodeDecodeError:
        return None
    if (
        not value
        or len(value) > MAX_STRING
        or any(ord(ch) < 0x20 or ord(ch) > 0x7E for ch in value)
    ):
        return None
    return value


def iter_qwords():
    for seg_ea in idautils.Segments():
        seg = ida_segment.getseg(seg_ea)
        name = ida_segment.get_segm_name(seg)
        if name not in {".rdata", ".data", "CONST"}:
            continue
        ea = (seg.start_ea + 7) & ~7
        while ea + 8 <= seg.end_ea:
            yield ea, ida_bytes.get_qword(ea)
            ea += 8


def read_fields(ea: int, count: int) -> tuple[Field, ...] | None:
    if count < 0 or count > 64:
        return None
    if count == 0:
        return ()
    if segment_for(ea) is None:
        return None

    fields = []
    # Field records are 24 bytes: name pointer, reserved/default pointer, type.
    for index in range(count):
        item = ea + index * 24
        name = read_ascii(ida_bytes.get_qword(item))
        reserved = ida_bytes.get_qword(item + 8)
        value_type = ida_bytes.get_qword(item + 16)
        if not name or value_type > 8:
            return None
        if reserved and segment_for(reserved) is None:
            return None
        fields.append(Field(name=name, value_type=value_type))
    return tuple(fields)


def extract_descriptors() -> list[Descriptor]:
    result: list[Descriptor] = []
    seen: set[tuple[str, str]] = set()

    for ea, first in iter_qwords():
        # Do not rely on idautils.Strings(): some releases have malformed IDA
        # string items (the "default" item can be split after four bytes).
        group = read_ascii(first)
        if group not in GROUPS:
            continue

        name_ptr = ida_bytes.get_qword(ea + 8)
        fields_ptr = ida_bytes.get_qword(ea + 16)
        fields_count = ida_bytes.get_qword(ea + 24)
        name = read_ascii(name_ptr)
        if not name or not (2 <= len(name) <= 256):
            continue

        fields = read_fields(fields_ptr, fields_count)
        if fields is None:
            continue

        key = (group, name)
        if key in seen:
            continue
        seen.add(key)
        result.append(
            Descriptor(
                address=f"0x{ea:X}",
                group=group,
                name=name,
                fields_address=f"0x{fields_ptr:X}" if fields_ptr else "",
                fields_count=fields_count,
                fields=fields,
            )
        )

    return sorted(result, key=lambda row: (row.group.lower(), row.name.lower()))


def write_outputs(rows: list[Descriptor]) -> tuple[str, str]:
    idb_path = idc.get_idb_path()
    stem, _ = os.path.splitext(idb_path)
    json_path = stem + ".features.json"
    csv_path = stem + ".features.csv"

    payload = []
    for row in rows:
        item = asdict(row)
        item["fields"] = [asdict(field) for field in row.fields]
        payload.append(item)

    with open(json_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)

    with open(csv_path, "w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "address",
                "group",
                "name",
                "fields_address",
                "fields_count",
                "fields",
            ],
        )
        writer.writeheader()
        for row in rows:
            writer.writerow(
                {
                    "address": row.address,
                    "group": row.group,
                    "name": row.name,
                    "fields_address": row.fields_address,
                    "fields_count": row.fields_count,
                    "fields": ";".join(
                        f"{field.name}:{TYPE_NAMES[field.value_type]}" for field in row.fields
                    ),
                }
            )
    return json_path, csv_path

def main():
    ida_kernwin.show_wait_box("Extracting KBaseConfigCenter feature descriptors...")
    try:
        rows = extract_descriptors()
        if not rows:
            raise RuntimeError("No validated feature descriptors were found")
        json_path, csv_path = write_outputs(rows)
    finally:
        ida_kernwin.hide_wait_box()

    print(f"[kbcc] extracted {len(rows)} descriptors")
    print(f"[kbcc] JSON: {json_path}")
    print(f"[kbcc] CSV:  {csv_path}")
    return rows


if __name__ == "__main__":
    main()
