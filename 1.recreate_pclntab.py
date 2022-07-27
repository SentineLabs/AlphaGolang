#Recreate pcln table in for stripped Go samples pre-compiler version 1.16
#Bruteforce function discovery and recreate .gopclntab segment
#(Most useful pre IDA 7.6)
import idc
import idautils
import idaapi

exists = False
for seg in idautils.Segments():
    name = idaapi.get_segm_name(idaapi.getseg(seg))
    if "gopclntab" in name:
        exists = True
        print("GoPCLNTab Found: %s" % name)
        break


info = idaapi.get_inf_structure()
try:
    is_be = info.is_be()
except:
    is_be = info.mf

lookup = "FF FF FF FB 00 00" if is_be else "FB FF FF FF 00 00"
v116magic = "FF FF FF FA 00 00" if is_be else "FA FF FF FF 00 00" #0xFFFFFFFA #Needs testing
v118magic = "FF FF FF F0 00 00" if is_be else "F0 FF FF FF 00 00"


if info.is_32bit():
    get_content = ida_bytes.get_dword
    multiplier = 4
if info.is_64bit():
    get_content = idc.get_qword
    multiplier = 8

halt = False
empty_counter = 0
seg_start = 0
seg_end = 0

ea = idc.find_binary(0, idc.SEARCH_DOWN, lookup)
if ea == idaapi.BADADDR:
    ea = idc.find_binary(0, idc.SEARCH_DOWN, v116magic)

if ea == idaapi.BADADDR:
    ea = idc.find_binary(0, idc.SEARCH_DOWN, v118magic)

if ea != idaapi.BADADDR:
    seg_start = ea
    print("Segment start (magic header): ", hex(seg_start))
    print("Bruteforcing function discovery based on pcln table")
    while (not halt):
        if empty_counter >= 3:
            seg_end = ea
            print("Effective .gopclntab seg_end: %s" % str(hex(seg_end)))
            halt = True
        offset_addr = get_content(ea)
        if offset_addr == 0:
            empty_counter += 1
            continue
        func_name = idc.get_func_name(offset_addr)
        if func_name == "":
            ida_bytes.del_items(offset_addr)
            idc.create_insn(offset_addr)
            ida_funcs.add_func(offset_addr)
        ea = ea + multiplier

    if not exists:
        if seg_end > seg_start:
            print("Creating .gopclntab: ", hex(seg_start), hex(seg_end))
            idaapi.add_segm(0, seg_start, seg_end, ".gopclntab", "DATA")
else:
    print("No magic header found T_T ")
