#IDAPython script to categorize golang functions into folders
import idaapi
import idautils
import ida_dirtree
import idc

func_dir: ida_dirtree.dirtree_t
func_dir =   ida_dirtree.get_std_dirtree(ida_dirtree.DIRTREE_FUNCS)
ite = ida_dirtree.dirtree_iterator_t()
ok = func_dir.findfirst(ite, "*")

folders = {}
for function in idautils.Functions():
    name = idc.get_func_name(function)
    folderName = ""
    if name.startswith("_") or name.startswith("."):
        folders.setdefault("uncategorized",[]).append(name)
        continue
    for i,c in enumerate(name):
        if c == "." or c == "_": 
            folderName = name[:i]
            break
    if folderName == "":
        folderName = "uncategorized"
    folders.setdefault(folderName,[]).append(name)
for folderName in folders:
    try:
        func_dir.mkdir(folderName)
    except:
        print("Failed to create folder: ", folderName)
        continue
    for name in folders[folderName]:
        try:
            func_dir.rename(name, folderName+"/"+name)
            #print("Moved: "+name+" to "+folderName)
        except:
            print("Failed to move function:", name)

common_packages = ["archive", "bufio", "builtin", "bytes", "compress", "container", "context", "crypto", "database", "debug", "embed", "encoding", "errors", "flag", "fmt", "go", "hash", "html", "image", "index", "io", "log", "math", "mime", "net", "os", "path", "plugin", "regexp", "sort", "strconv", "strings", "sync", "syscall", "testing", "text", "time", "unicode", "unsafe", "internal", "reflect", "vendor", "golang", "runtime", "type"]

folderName = "StandardGoPackages"

try:
    func_dir.mkdir(folderName)
    #print("Created folder: ", folderName)    
    for package in common_packages:
        try:
            func_dir.rename(package, folderName+"/"+package)
            #print("Moved: "+name+" to "+folderName)
        except:
            print("Failed to move standard package folder:", package)
except:
    print("Failed to create folder: ", folderName)
