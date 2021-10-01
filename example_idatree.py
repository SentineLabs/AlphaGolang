#This works for lumina functions
import ida_dirtree

func_dir: ida_dirtree.dirtree_t
func_dir = ida_dirtree.get_std_dirtree(ida_dirtree.DIRTREE_FUNCS)
ite = ida_dirtree.dirtree_iterator_t()
ok = func_dir.findfirst(ite, "*")
to_move = []
func_dir.mkdir("lumina")
while ok:
    cur: ida_dirtree.dirtree_cursor_t = ite.cursor
    de:ida_dirtree.direntry_t = func_dir.resolve_cursor(cur)
    attrs = func_dir.get_entry_attrs(de)
    abspath:str = func_dir.get_abspath(cur)
    print(f"idx: {de.idx:#x} isdir: {de.isdir} attrs: {attrs} abspath: {abspath}")
    ok = func_dir.findnext(ite)
    if "M" in attrs:
        to_move.append(abspath)

for abspath in to_move:    
    func_dir.rename(abspath, "lumina/"+abspath)
