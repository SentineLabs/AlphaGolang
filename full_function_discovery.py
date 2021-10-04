'''
    Refactoring Tim Strazzere's Golang Loader Assist
    Split full function discovery, function renaming, and function ptr renaming
'''

from idautils import *
from idc import *
import idaapi
import ida_segment
import sys
import string

#
# Constants
#
DEBUG = False

#
# Utility functions
#
def info(formatted_string):
    print(formatted_string)

def error(formatted_string):
    print('ERROR - %s' % formatted_string)

def debug(formatted_string):
    if DEBUG:
        print('DEBUG - %s' % formatted_string)

#
# Function defining methods
#

def get_text_seg():
    #   .text found in PE & ELF binaries, __text found in macho binaries
    return _get_seg(['.text', '__text'])

def get_gopclntab_seg():
    # .gopclntab found in (older) PE & ELF binaries, __gopclntab found in macho binaries,
    # runtime.pclntab in .rdata for newer PE binaries
    # JAGS -- MODIFIED TO CREATE GOPCLNTAB segment if it's not already there
    seg = _get_seg_from_rdata(['runtime.pclntab'])

    if seg is None:
        seg =  _get_seg(['.gopclntab', '__gopclntab'])

    return seg

def _get_seg(possible_seg_names):
    for seg_name in possible_seg_names:
        seg = ida_segment.get_segm_by_name(seg_name)
        if seg:
            return seg

    return None

def _get_seg_from_rdata(possible_seg_names):
    for seg_name in possible_seg_names:
        for ea, name in Names():
            if name == seg_name:
                return ea

    return None

# Indicators of runtime_morestack
# mov     large dword ptr ds:1003h, 0 # most I've seen
# mov     qword ptr ds:1003h, 0 # some

def is_simple_wrapper(addr):
    if idc.print_insn_mnem(addr) == 'xor' and idc.print_operand(addr, 0) == 'edx' and  idc.print_operand(addr, 1) == 'edx':
        addr = ida_search.find_code(addr, SEARCH_DOWN)
        if idc.print_insn_mnem(addr) == 'jmp' and idc.print_operand(addr, 0) == 'runtime_morestack':
            return True

    return False

def create_runtime_ms():
    debug('Attempting to find runtime_morestack function for hooking on...')

    text_seg = get_text_seg()
    if text_seg is None:
        debug('Failed to get text segment')
        return None

    #   Opcodes for "mov     large dword ptr ds:1003h, 0", binary search is faster than text search
    opcodes = 'c7 05 03 10 00 00 00 00 00 00'
    if idaapi.get_inf_structure().is_64bit():
        #   Opcodes for "mov     qword ptr ds:dword_1000+3, 0"
        opcodes = '48 c7 04 25 03 10 00 00 00 00 00 00'

    runtime_ms_end = idaapi.find_binary(text_seg.start_ea, text_seg.end_ea, opcodes, 0, SEARCH_DOWN)
    if runtime_ms_end == BADADDR:
        debug('Failed to find opcodes associated with runtime_morestack: %s' % opcodes)
        return None

    runtime_ms = idaapi.get_func(runtime_ms_end)
    if runtime_ms is None:
        debug('Failed to get runtime_morestack function from address @ 0x%x' % runtime_ms_end)
        return None

    if idc.set_name(runtime_ms.start_ea, "runtime_morestack", SN_PUBLIC):
        debug('Successfully found runtime_morestack')
    else:
        debug('Failed to rename function @ 0x%x to runtime_morestack' % runtime_ms.start_ea)

    return runtime_ms

def traverse_xrefs(func):
    func_created = 0

    if func is None:
        return func_created

    # First
    func_xref = idaapi.get_first_cref_to(func.start_ea)
    # Attempt to go through crefs
    while func_xref != BADADDR:
        # See if there is a function already here
        if idaapi.get_func(func_xref) is None:
            # Ensure instruction bit looks like a jump
            func_end = ida_search.find_code(func_xref, SEARCH_DOWN)
            if idc.print_insn_mnem(func_end) == "jmp":
                # Ensure we're jumping back "up"
                func_start = idc.get_operand_value(func_end, 0)
                if func_start < func_xref:
                    if ida_funcs.add_func(func_start, func_end):
                        func_created += 1
                    else:
                        # If this fails, we should add it to a list of failed functions
                        # Then create small "wrapper" functions and backtrack through the xrefs of this
                        error('Error trying to create a function @ 0x%x - 0x%x' %(func_start, func_end))
        else:
            xref_func = idaapi.get_func(func_xref)
            # Simple wrapper is often runtime_morestack_noctxt, sometimes it isn't though...
            if is_simple_wrapper(xref_func.start_ea):
                debug('Stepping into a simple wrapper')
                func_created += traverse_xrefs(xref_func)
            if idaapi.get_func_name(xref_func.start_ea) is not None and 'sub_' not in idaapi.get_func_name(xref_func.start_ea):
                debug('Function @0x%x already has a name of %s; skipping...' % (func_xref, idaapi.get_func_name(xref_func.start_ea)))
            else:
                debug('Function @ 0x%x already has a name %s' % (xref_func.start_ea, idaapi.get_func_name(xref_func.start_ea)))

        func_xref = idaapi.get_next_cref_to(func.start_ea, func_xref)

    return func_created

def find_func_by_name(name):
    text_seg = get_text_seg()
    if text_seg is None:
        return None

    for addr in Functions(text_seg.start_ea, text_seg.end_ea):
        if name == idaapi.get_func_name(addr):
            return idaapi.get_func(addr)

    return None

def runtime_init():
    func_created = 0

    if find_func_by_name('runtime_morestack') is not None:
        func_created += traverse_xrefs(find_func_by_name('runtime_morestack'))
        func_created += traverse_xrefs(find_func_by_name('runtime_morestack_noctxt'))
    else:
        runtime_ms = create_runtime_ms()
        func_created = traverse_xrefs(runtime_ms)


    return func_created


#
# Function renaming fuctionality
#

def create_pointer(addr, force_size=None):
    if force_size != 4 and (idaapi.get_inf_structure().is_64bit() or force_size == 8):
        ida_bytes.create_data(addr, FF_QWORD, 8, ida_idaapi.BADADDR)
        return idc.get_qword(addr), 8
    else:
        ida_bytes.create_data(addr, FF_DWORD, 4, ida_idaapi.BADADDR)
        return idc.get_wide_dword(addr), 4

STRIP_CHARS = [ '(', ')', '[', ']', '{', '}', ' ', '"' ]
REPLACE_CHARS = ['.', '*', '-', ',', ';', ':', '/', '\xb7' ]
def clean_function_name(name):
    name = name.decode("utf-8") 
    # Kill generic 'bad' characters
    clean_name = ""
    for c in name:
        if c not in string.printable or c in STRIP_CHARS:
            continue
        elif c in REPLACE_CHARS:
            clean_name += "_"
        else:
            clean_name += c    
    return clean_name

def renamer_init():
    renamed = 0

    gopclntab = get_gopclntab_seg()
#   if goplcntab is None:
#   add my code here
    if gopclntab is not None:
        info('type : %s' % type(gopclntab))
        start_ea = 0
        if isinstance(gopclntab, int):
            start_ea = gopclntab
        else:
            start_ea = gopclntab.start_ea
        # Skip unimportant header and goto section size
        addr = start_ea + 8
        size, addr_size = create_pointer(addr)
        addr += addr_size

        # Unsure if this end is correct
        early_end = addr + (size * addr_size * 2)
        while addr < early_end:
            func_offset, addr_size = create_pointer(addr)
            name_offset, addr_size = create_pointer(addr + addr_size)
            addr += addr_size * 2

            func_name_addr = idc.get_wide_dword(name_offset + start_ea + addr_size) + start_ea
            func_name = ida_bytes.get_strlit_contents(func_name_addr, -1, STRTYPE_C)
            try:
                ida_bytes.create_strlit(func_name_addr, len(func_name), STRTYPE_C)
            except:
                continue
            appended = clean_func_name = clean_function_name(func_name)
            debug('Going to remap function at 0x%x with %s - cleaned up as %s' % (func_offset, func_name, clean_func_name))
            if idaapi.get_func_name(func_offset) is not None:
                if idc.set_name(func_offset, clean_func_name):
                    renamed += 1
                else:
                    error('clean_func_name error %s' % clean_func_name)

    return renamed


# Function pointers are often used instead of passing a direct address to the
# function -- this function names them based off what they're currently named
# to ease reading
#
# lea     rax, main_GetExternIP_ptr <-- pointer to actual function
# mov     [rsp+1C0h+var_1B8], rax <-- loaded as arg for next function
# call    runtime_newproc <-- function is used inside a new process

def pointer_renamer():
    renamed = 0

    text_seg = get_text_seg()
    if text_seg is None:
        debug('Failed to get text segment')
        return renamed

    for addr in Functions(text_seg.start_ea, text_seg.end_ea):
        name = idc.get_func_name(addr)

        # Look at data xrefs to the function - find the pointer that is located in .rodata
        data_ref = idaapi.get_first_dref_to(addr)
        while data_ref != BADADDR:
            if 'rodata' in get_segm_name(data_ref):
                # Only rename things that are currently listed as an offset; eg. off_9120B0
                if 'off_' in ida_name.get_ea_name(data_ref):
                    if idc.set_name(data_ref, ('ptr_%s' % name)):
                        renamed += 1
                    else:
                        error('error attempting to name pointer @ 0x%02x for %s' % (data_ref, name))

            data_ref = idaapi.get_next_dref_to(addr, data_ref)

    return renamed

def main():

    # This should be run before the renamer, as it will find and help define more functions
    func_added = runtime_init()
    info('Found and successfully created %d functions!' % func_added)

    # Should be run after the function initializer,
    renamed = renamer_init()
    info('Found and successfully renamed %d functions!' % renamed)

    # Attempt to rename all function pointers after we have all the functions and proper function names
    pointers_renamed = pointer_renamer()
    info('Found and successfully renamed %d function pointers!' % pointers_renamed)

if __name__ == "__main__":
    main()
