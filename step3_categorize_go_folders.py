#IDAPython script to categorize golang functions into folders
#Turn on "Show Folders" to see effects
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
    if folderName == "sub":
        folderName = "unnamed"
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

common_packages = ["archive", "bufio", "builtin", "bytes", "compress", "container", "context", "crypto", "database", "debug", "embed", "encoding", "errors", "flag", "fmt", "go", "hash", "html", "image", "index", "io", "log", "math", "mime", "net", "os", "path", "plugin", "regexp", "sort", "strconv", "strings", "sync", "syscall", "testing", "text", "time", "unicode", "unsafe", "internal", "reflect", "vendor", "golang", "runtime", "type", "setg", "pthread"]

folderName = "StandardGoPackages"

try:
    func_dir.mkdir(folderName)
    for package in common_packages:
        try:
            func_dir.rename(package, folderName+"/"+package)
        except:
            print("Failed to move standard package folder:", package)
except:
    print("Failed to create folder: ", folderName)


if "github" in folders:
    github_repos = {}
    for package in folders["github"]:
        repo = ""
        for i,c in enumerate(package[11:]):
            if c == "." or c == "_": 
                i = i+11
                repo = package[11:i]
                github_repos.setdefault(repo,[]).append(package)
                break

    for repo in github_repos:
        sub_folder = "github/" + repo
        try:
            func_dir.mkdir(sub_folder)
        except:
            print("Failed to create folder: ", sub_folder)
        for func in github_repos[repo]:
            try:
                func_dir.rename("github/"+func, sub_folder+"/"+func)
            except:
                print("Failed to move github repo:", func)
