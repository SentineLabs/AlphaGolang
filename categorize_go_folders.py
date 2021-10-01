#IDAPython script to categorize golang functions into folders
import idaapi
import idautils
import ida_dirtree
import idc

func_dir: ida_dirtree.dirtree_t
func_dir = ida_dirtree.get_std_dirtree(ida_dirtree.DIRTREE_FUNCS)
ite = ida_dirtree.dirtree_iterator_t()
ok = func_dir.findfirst(ite, "*")

folders = {}
uncategorized = []

for function in idautils.Functions():
    name = idc.get_func_name(function)
    try:
        index = name.index("_")
        index2 = name.index(".")
        if index2 < index:
            index = index2
        folderName = name[:index]
    except:
        uncategorized.append(name)
        continue
    if folderName in folders:
        folders[folderName].append(name)
    else:
        folders[folderName] = [name]
for folderName in folders:
        try:
            func_dir.mkdir(folderName)
            #print("Created folder: ", folderName)    
        except:
            print("Failed to create folder: ", folderName)
            continue
        for name in folders[folderName]:
            try:
                func_dir.rename(name, folderName+"/"+name)
                #print("Moved: "+name+" to "+folderName)
            except:
                print("Failed to move function:", name)

folderName = "uncategorized"
try:
    func_dir.mkdir(folderName)
    #print("Created folder: ", folderName)    
    for name in uncategorized:
        try:
            func_dir.rename(name, folderName+"/"+name)
            #print("Moved: "+name+" to "+folderName)
        except:
            print("Failed to move uncategorized function:", name)
except:
    print("Failed to create folder: ", folderName)
    

