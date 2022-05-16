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

def find_type_structures(func_name, search_len=15):
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
                # Find the type argument of that function
                for h in Heads(ref.frm - search_len, ref.frm):
                    print(f"Instruction: {hex(h)} - {print_insn_mnem(h)}")
                    if "lea" == print_insn_mnem(h) and (get_operand_type(h, 1) == o_imm or get_operand_type(h, 1) == o_mem) and (print_operand(h, 0) == "rcx" or print_operand(h, 0) == "rax"):
                        print("FOUND")
                        type_addresses.add(get_operand_value(h, 1))
                        break
            break
    return type_addresses


def parse_type(addr):
	"""
	Applies the correct structure to the type at the given address and locates its name.
	"""
	SetType(addr, "golang_type")
	data_addr = -1
	for s in Segments():
		if (get_segm_name(s) == ".rdata") or (get_segm_name(s) == "__rodata"):
		   data_addr = get_segm_start(s)
	if data_addr == -1:
		print("Could not find .rdata segment!")
		return False
		   
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
	return True

# Import the required IDA structures if necessary
if get_struc_id("golang_type") == BADADDR:
    parse_decls(C_HEADER, idaapi.PT_TYP)

# Find all places in the binary where there is type information
addresses  = find_type_structures("runtime.newobject")
addresses |= find_type_structures("runtime.makechan", search_len=30)
addresses |= find_type_structures("runtime.makemap", search_len=30)
addresses |= find_type_structures("runtime.mapiterinit", search_len=30)
addresses |= find_type_structures("runtime.makeslice", search_len=30)

# Parse type information
for t in addresses:
    if not parse_type(t):
        break  # Stop on first fatal error
