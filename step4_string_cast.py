'''
Fix string casts by reference to the loading functions
Refactored from Tim Strazzere's GolangLoaderAssist

Fixed:
>Added routine to undefine strings that are too long and thereby suspect before attempting to create new strings based on string loading routines
>Added logic to undefine items in the target offset when retrying string casting, drastically better results
>Added sanity checks for intended string address

Needs:
>Better string load heuristics
'''
from idautils import *
from idc import *
import idaapi
import ida_bytes
import idautils
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

#Undefine obviously bad string definitions:
def undefine_string(ea):
    ida_bytes.del_items(ea)
    debug("Deleted string @ offset %s" % hex(ea))   

def undefine_long_strings(len_boundary):
    counter = 0
    for s in idautils.Strings():
        if s.length > len_boundary:
            undefine_string(s.ea)
            counter += 1
    return counter


#
# String defining fuctionality
#

# Indicators of string loads
# mov     ebx, offset aWire ; "wire" # Get string
# mov     [esp], ebx
# mov     dword ptr [esp+4], 4 # String length

# mov     ebx, offset unk_8608FD5 # Get string
# mov     [esp+8], ebx
# mov     dword ptr [esp+0Ch], 0Eh # String length

# mov     ebx, offset unk_86006E6 # Get string
# mov     [esp+10h], ebx
# mov     dword ptr [esp+14h], 5 # String length

# mov     ebx, 861143Ch
# mov     dword ptr [esp+0F0h+var_E8+4], ebx
# mov     [esp+0F0h+var_E0], 19h

# Found in newer versions of golang binaries

# lea     rax, unk_8FC736
# mov     [rsp+38h+var_18], rax
# mov     [rsp+38h+var_10], 1Dh

# lea     rdx, unk_8F6E82
# mov     [rsp+40h+var_38], rdx
# mov     [rsp+40h+var_30], 13h

# lea     eax, unk_82410F0
# mov     [esp+94h+var_8C], eax
# mov     [esp+94h+var_88], 2


# Currently it's normally ebx, but could in theory be anything - seen ebp
VALID_REGS = ['eax', 'ebx', 'ebp', 'rax', 'rcx', 'r10', 'rdx']

# Currently it's normally esp, but could in theory be anything - seen eax
VALID_DEST = ['esp', 'eax', 'ecx', 'edx', 'rsp']

# This logic is from GolangLoaderAssist. Needs to be broken up, refactored, and improved
def is_string_load(addr):
    patterns = []
    # Check for first parts instruction and what it is loading -- also ignore function pointers we may have renamed
    if (idc.print_insn_mnem(addr) != 'mov' and idc.print_insn_mnem(addr) != 'lea') and (idc.get_operand_type(addr, 1) != 2 or idc.get_operand_type(addr, 1) != 5) or idc.print_operand(addr, 1)[-4:] == '_ptr':
        return False

    # Validate that the string offset actually exists inside the binary
    if get_segm_name(idc.get_operand_value(addr, 1)) is None:
        return False

    # Could be unk_, asc_, 'offset ', XXXXh, ignored ones are loc_ or inside []
    if idc.print_operand(addr, 0) in VALID_REGS and not ('[' in idc.print_operand(addr, 1) or 'loc_' in idc.print_operand(addr, 1)) and (('offset ' in idc.print_operand(addr, 1) or 'h' in idc.print_operand(addr, 1)) or ('unk' == idc.print_operand(addr, 1)[:3])):
        from_reg = idc.print_operand(addr, 0)
        # Check for second part
        addr_2 = ida_search.find_code(addr, SEARCH_DOWN)
        try:
            dest_reg = idc.print_operand(addr_2, 0)[idc.print_operand(addr_2, 0).index('[') + 1:idc.print_operand(addr_2, 0).index('[') + 4]
        except ValueError:
            return False
        if idc.print_insn_mnem(addr_2) == 'mov' and dest_reg in VALID_DEST and ('[%s' % dest_reg) in idc.print_operand(addr_2, 0) and idc.print_operand(addr_2, 1) == from_reg:
            # Check for last part, could be improved
            addr_3 = ida_search.find_code(addr_2, SEARCH_DOWN)
            # idc.get_operand_type 1 is a register, potentially we can just check that idc.get_operand_type returned 5?
            if idc.print_insn_mnem(addr_3) == 'mov' and (('[%s+' % dest_reg) in idc.print_operand(addr_3, 0) or idc.print_operand(addr_3, 0) in VALID_DEST) and 'offset ' not in idc.print_operand(addr_3, 1) and 'dword ptr ds' not in idc.print_operand(addr_3, 1) and idc.get_operand_type(addr_3, 1) != 1 and idc.get_operand_type(addr_3, 1) != 2 and idc.get_operand_type(addr_3, 1) != 4:
                try:
                    dumb_int_test = idc.get_operand_value(addr_3, 1)
                    if dumb_int_test > 0 and dumb_int_test < sys.maxsize:
                        return True
                except ValueError:
                    return False

    return False

def create_string(addr, string_len):
    if get_segm_name(addr) is None:
        debug('Cannot load a string which has no segment - not creating string @ 0x%02x' % addr)
        return False

    debug('Found string load @ 0x%x with length of %d' % (addr, string_len))
    # This may be overly aggressive if we found the wrong area...
    if idc.get_str_type(addr) is not None and ida_bytes.get_strlit_contents(addr, string_len, STRTYPE_C) is not None and len(ida_bytes.get_strlit_contents(addr, string_len, STRTYPE_C)) != string_len:
        debug('It appears that there is already a string present @ 0x%x' % addr)
        try:
            ida_bytes.del_items(addr, string_len, ida_bytes.DELIT_SIMPLE)
        except:
            print("Failed delete")

    if ida_bytes.get_strlit_contents(addr, string_len, STRTYPE_C) is None and ida_bytes.create_strlit(addr, string_len, STRTYPE_C):
        return True
    else:
        # If something is already partially analyzed (incorrectly) we need to ida_bytes.del_items it
        try:
            ida_bytes.del_items(addr, string_len, ida_bytes.DELIT_SIMPLE)
        except:
            print("Failed delete")
        if ida_bytes.create_strlit(addr, string_len, STRTYPE_C):
            return True
        debug('Unable to make a string @ 0x%x with length of %d' % (addr, string_len))

    return False

def create_offset(addr):
    if ida_offset.op_plain_offset(addr, 1, 0):
        return True
    else:
        debug('Unable to make an offset for string @ 0x%x ' % addr)

    return False

def strings_init():
    strings_added = 0
    retry = []
    text_seg = get_text_seg()
    if text_seg is None:
        debug('Failed to get text segment')
        return strings_added

    # This may be inherently flawed as it will only search for defined functions
    # and as of IDA Pro 6.95 it fails to autoanalyze many GO functions, currently
    # this works well since we redefine/find (almost) all the functions prior to
    # this being used. Could be worth a strategy rethink later one or on diff archs

    for addr in Functions(text_seg.start_ea, text_seg.end_ea):
        name = idc.get_func_name(addr)

        end_addr = next(Chunks(addr))[1]
        if end_addr < addr:
            error('Unable to find good end for the function %s' % name)
            pass

        debug('Found function %s starting/ending @ 0x%x 0x%x' %  (name, addr, end_addr))

        while addr <= end_addr:
            if is_string_load(addr):
                if 'rodata' not in get_segm_name(addr) and 'text' not in get_segm_name(addr):
                    debug('Should a string be in the %s section?' % get_segm_name(addr))
                string_addr = idc.get_operand_value(addr, 1)
                addr_3 = ida_search.find_code(ida_search.find_code(addr, SEARCH_DOWN), SEARCH_DOWN)
                string_len = idc.get_operand_value(addr_3, 1)
                undefine_string(string_addr)
                if create_string(string_addr, string_len):
                    if create_offset(addr):
                        strings_added += 1
                else:
                    # There appears to be something odd that goes on with IDA making some strings, always works
                    # the second time, so lets just force a retry...
                    if string_len < 120:
                        retry.append((addr, string_addr, string_len))

                # Skip the extra mov lines since we know it won't be a load on any of them
                addr = ida_search.find_code(addr_3, SEARCH_DOWN)
            else:
                addr = ida_search.find_code(addr, SEARCH_DOWN)

    for instr_addr, string_addr, string_len in retry:
        try:
            if string_addr > ida_segment.get_last_seg().end_ea:
                continue
        except:
            debug("String retry addr check fallthrough")
        undefine_string(ida_bytes.get_item_head(string_addr)) #Attempt to undefine after first failed attempt to define string
        if create_string(string_addr, string_len):
            if create_offset(instr_addr):
                strings_added += 1
        else:
            error('FAILED-RETRY : Unable to make a string @ 0x%x with length of %d for usage in function @ 0x%x' % (string_addr, string_len, instr_addr))

    return strings_added

def main():
# Attempt to find all string loading idioms

    #Prep
    undefinedCount = undefine_long_strings(50) #Feel free to fiddle with len
    info('Undefined %d suspected bad strings' % undefinedCount)
    strings_added = strings_init()
    info('Found and successfully created %d strings!' % strings_added)


if __name__ == "__main__":
    main()

