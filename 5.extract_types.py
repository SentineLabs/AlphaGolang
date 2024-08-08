"""
go_tmilk.py - Go Type Milking
Written by Ivan Kwiatkowski @ Kaspersky GReAT
Shared under the terms of the GPLv3 license
"""

C_HEADER = """
enum golang_kind : __int8
{
  INVALID = 0x0,
  BOOL = 0x1,
  INT = 0x2,
  INT8 = 0x3,
  INT16 = 0x4,
  INT32 = 0x5,
  INT64 = 0x6,
  UINT = 0x7,
  UINT8 = 0x8,
  UINT16 = 0x9,
  UINT32 = 0xA,
  UINT64 = 0xB,
  UINTPTR = 0xC,
  FLOAT32 = 0xD,
  FLOAT64 = 0xE,
  COMPLEX64 = 0xF,
  COMPLEX128 = 0x10,
  ARRAY = 0x11,
  CHAN = 0x12,
  FUNC = 0x13,
  INTERFACE = 0x14,
  MAP = 0x15,
  PTR = 0x16,
  SLICE = 0x17,
  STRING = 0x18,
  STRUCT = 0x19,
  UNSAFEPTR = 0x1A,
  CHAN_DIRECTIFACE = 0x32,
  FUNC_DIRECTIFACE = 0x33,
  MAP_DIRECTIFACE = 0x35,
  STRUCT_DIRECTIFACE = 0x39,
};

struct golang_type
{
  __int64 size;
  __int64 ptrdata;
  int hash;
  char tflag;
  char align;
  char fieldalign;
  golang_kind kind;
  __int64 equal_fn;
  __int64 gcData;
  int nameoff;
  int typeoff;
  __int64 name;
  __int64 mhdr;
};
"""
DEBUG = False
cache_data_addr = -1

def find_type_structures(func_name, valid_register, search_len=15):
    """
    Looks for all types passed as argument to the given function. Probably only
    works for Go > 1.15 where the register calling convention was introduced.
    
    func_name: The name of the function to look for (i.e. "runtime.newobject")
    register: The register in which the required argument is passed (i.e. "eax")
    """
    type_addresses = set()
    # Find all xrefs to the given function
    for f in Functions():
        if ida_funcs.get_func_name(f) == func_name:
            for ref in XrefsTo(f):

                # Check that reference is defined as code 
                if not is_code(idaapi.get_flags(ref.frm)):
                    continue

                # Find the type argument of that function in reverse order
                for h in reversed(list(Heads(ref.frm - search_len, ref.frm))):
                    print(f"Instruction: {hex(h)} - {print_insn_mnem(h)}")
                    if "lea" == print_insn_mnem(h) and (get_operand_type(h, 1) ==o_imm or get_operand_type(h, 1) == o_mem):
                        
                        if (print_operand(h, 0) == valid_register):#(print_operand(h, 0) == "rcx" or print_operand(h, 0) == "rax"or print_operand(h, 0) == "rdi"):
                            print("FOUND")
                            type_addresses.add(get_operand_value(h, 1))
                            break
                        
            break # No need to loop through other functions since we have found our function
    return type_addresses

def is_in_segments(ea):
    # Iterate over all segments
    for i in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(i)
        if seg is None:
            continue

        # Get segment boundaries
        start_ea = seg.start_ea
        end_ea = seg.end_ea

        # Check if the address is within this segment
        if start_ea <= ea < end_ea:
            return True

    return False

def print_debug_msg(msg):
    if DEBUG:
        print(msg)

def undefine_range(start_addr, size):
    
    for offset in range(size): 
        ida_bytes.del_items(start_addr + offset)

def define_qword(start_addr, num_qword):
     
    for idx in range(num_qword):
        create_data(start_addr+idx*8, FF_QWORD, 8, BADADDR)


def get_struct_variable_name(addr):

    ## Unsure of what the first byte refer to
    # variable_name_header = ida_bytes.get_byte(addr)
    # if variable_name_header != 1 and variable_name_header != 3 and variable_name_header != 0:
    #     print_debug_msg(str(hex(addr)) + ' - Invalid variable name header')
    #     return ''
    
    variable_name_len = ida_bytes.get_byte(addr+1)
    variable_name = ida_bytes.get_strlit_contents(addr+2, variable_name_len, STRTYPE_C)

    return variable_name

def parse_struct_variables(start_ea, num_variables):

    undefine_range(start_ea, num_variables*3*0x8)
    define_qword(start_ea, num_variables*3)

    # Parse each variable in struct
    for variable_idx in range(num_variables):
        # variable consists of the following pattern
        # ptr_to_name_of_variable
        # variable_type
        # offset
        curr_ea = start_ea+variable_idx*0x8*3
        
        # Get name and set cmt next to the pointer
        variable_name_ptr = get_qword(curr_ea)
        variable_name = get_struct_variable_name(variable_name_ptr)

        if variable_name is not None:
            set_cmt(curr_ea, variable_name.decode(errors="replace"), False)

        # Ensure that the type is resolved if not resolve the type
        if idc.get_type(get_qword(curr_ea+8)) != 'golang_type':
            print_debug_msg("Parsing type of variable at " + str(hex(curr_ea+8)))
            parse_type(get_qword(curr_ea+8))

def get_data_addr():

    global cache_data_addr

    if cache_data_addr != -1:
        return cache_data_addr
    

    data_addr = -1

    # This doesn't seem reliable because it might not be the data segment we want in
    # some samples
    # for s in Segments():
    #     if (get_segm_name(s) == ".rdata") or (get_segm_name(s) == "__rodata"):
    #        data_addr = get_segm_start(s)
    #        cache_data_addr = data_addr
    

    if data_addr == -1:
        # Could be due to various reasons
        # - Tampered sections
        # - Dumped from memory
        # Try searching for it
        _rdata_magic = b"\x00\x00\x01\x01\x41\x01\x01\x42"
        mask = bytes([0xFF] * len(_rdata_magic))

        seg_qty = ida_segment.get_segm_qty()

        for seg_idx in range(seg_qty):
            seg = ida_segment.getnseg(seg_idx)
            if seg is None:
                continue

            start_ea = seg.start_ea
            end_ea = seg.end_ea
            
            found_ea = ida_bytes.bin_search(start_ea, end_ea, _rdata_magic, mask, ida_search.SEARCH_DOWN, 0)

            
            if found_ea != idaapi.BADADDR:
                data_addr = found_ea
                cache_data_addr = data_addr
                return data_addr
        print("Could not find .rdata segment!")
        return data_addr
    else:
        return data_addr

def parse_struct_with_name(addr):
    # variable_size - offset 0x40
    # variable_size - offset 0x48
    # offset_ptr_to_module_name - offset 0x50
    # |_ 0
    # |_ size
    # |_ string
    # size of structure - offset 0x58
    # Start of variable

    data_addr = cache_data_addr

    

    variable_size = get_qword(addr+0x40)
    offset_ptr_to_module_name = get_qword(addr+0x50)
    module_name = data_addr + offset_ptr_to_module_name


    
    # Check whether module_name is within segments
    if is_in_segments(module_name):

        if get_wide_byte(module_name) == 0:
            name_size = get_wide_byte(module_name+1)
            module_name_str = get_strlit_contents(module_name+2, name_size)
            set_cmt(addr+0x50, module_name_str.decode(errors="replace"), False)
        else:
            print_debug_msg(hex(module_name))
            print_debug_msg(get_wide_byte(module_name))
            print_debug_msg("Invalid name")

    

    size_of_next_structure = get_qword(addr+0x58)

    undefine_range(addr+0x40, 0x20)
    define_qword(addr+0x40, 0x4)

    variable_start_addr = get_qword(addr+0x38)
    parse_struct_variables(variable_start_addr, variable_size)




def parse_struct_without_name(addr):
    # variable_size - offset 0x40
    # variable_size - offset 0x48
    # Start of variable
    variable_size = get_qword(addr+0x40)

    undefine_range(addr+0x40, 0x10)

    define_qword(addr+0x40, 2)

    # Parse each variable of struct
    variable_start_addr = get_qword(addr+0x38)
    parse_struct_variables(variable_start_addr, variable_size)
    




def parse_member(addr):
    # Supports only struct type
    if get_wide_byte(addr+0x17) != 0x19:
        print_debug_msg(str(hex(addr)) + " - Not struct type")
        return

    if get_qword(addr+0x40) == get_qword(addr+0x48): # Ensure the two values are equal so we can safely assume member_size
        
        if get_wide_byte(addr+0x14) & 0x4 != 0: # Tflags has name - https://github.com/golang/go/blob/release-branch.go1.23/src/internal/abi/type.go#L109
            parse_struct_with_name(addr)
        else:
            parse_struct_without_name(addr)         
            
    else:
        print_debug_msg(str(hex(addr)) + " - Unmatched member size")
        return
    



def parse_type(addr):
    """
    Applies the correct structure to the type at the given address and locates its name.
    """
    SetType(addr, "golang_type")
    data_addr = get_data_addr()
           
    # nameOff is an offset into rdata. We end up on a structure where the first byte is a bitfield
    # followed by the size of the string followed by the name of the type.
    # https://github.com/golang/go/blob/release-branch.go1.16/src/reflect/type.go#L443
    nameOff = get_wide_dword(addr + 0x28) + data_addr
    
    
    if nameOff == data_addr:
        return True  # No type string, just move on
        
    # Starting from Go 1.17 (?), the size is provided as a varint-encoded length.
    size = get_wide_byte(nameOff + 1) << 8 | get_wide_byte(nameOff + 2)
    
    if size > 0xFF:  # Quick & dirty sanity check.
        size = get_wide_byte(nameOff + 1)  # This is almost certain to break eventually
        type_str = get_strlit_contents(nameOff + 2, size)
    else:
        type_str = get_strlit_contents(nameOff + 3, size)
    if not type_str:
        print(f"Could not obtain type name for {hex(addr)} at address {hex(nameOff)}")
        del_items(addr)  # Was probably a FP, delete the structure and move on
        return True
    set_cmt(addr, type_str.decode(errors="replace"), False)
    for ref in XrefsTo(addr):
        set_cmt(ref.frm, type_str.decode(errors="replace"), False)
    # Rename the structure too. 0x800 = SN_FORCE, not available for some reason
    # See https://hex-rays.com/products/ida/support/idadoc/203.shtml
    set_name(addr, "type_" + type_str.decode(errors="replace")[:20], SN_NOCHECK | 0x800)
    parse_member(addr)
    return True

# Import the required IDA structures if necessary
if get_struc_id("golang_type") == BADADDR:
    parse_decls(C_HEADER, idaapi.PT_TYP)

# Find all places in the binary where there is type information
addresses  = find_type_structures("runtime_newobject", "rax")
addresses |= find_type_structures("runtime_makechan", "rax", search_len=30)
addresses |= find_type_structures("runtime_makemap", "rax", search_len=30)
addresses |= find_type_structures("runtime_mapiterinit", "rax", search_len=30)
addresses |= find_type_structures("runtime_makeslice", "rax", search_len=30)
addresses |= find_type_structures("runtime_makeslicecopy", "rax", search_len=30)
addresses |= find_type_structures("encoding_json_Unmarshal", "rdi", search_len=30)
addresses |= find_type_structures("encoding_json_Marshal", "rax", search_len=30)
addresses |= find_type_structures("runtime_typedslicecopy", "rax", search_len=30)
addresses |= find_type_structures("runtime_growslice", "rsi", search_len=30)
addresses |= find_type_structures("runtime_assertI2I2", "rax", search_len=30)
addresses |= find_type_structures("runtime_assertI2I", "rax", search_len=30)
addresses |= find_type_structures("runtime_assertE2I", "rax", search_len=30)
addresses |= find_type_structures("runtime_assertE2I2", "rax", search_len=30)
addresses |= find_type_structures("golang_org_x_crypto_ssh_Unmarshal", "rdi", search_len=30)
addresses |= find_type_structures("runtime_typedmemclr", "rax", search_len=30)



# Parse type information
for t in addresses:
    if not parse_type(t):
        break  # Stop on first fatal error
