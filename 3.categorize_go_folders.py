#IDAPython script to categorize golang functions into folders
#Turn on "Show Folders" to see effects
import ida_dirtree
import idautils
import idc

func_dir: ida_dirtree.dirtree_t
func_dir =   ida_dirtree.get_std_dirtree(ida_dirtree.DIRTREE_FUNCS)
ite = ida_dirtree.dirtree_iterator_t()
ok = func_dir.findfirst(ite, "*")

folders = {}


def create_folders():
    for function in idautils.Functions():
        folderName = ""
        name = idc.get_func_name(function)
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
    existed = []
    created = []
    for folderName in folders:
        if func_dir.isdir(folderName):
            existed.append(folderName)
            continue
        else:
            try:
                func_dir.mkdir(folderName)
                created.append(folderName)
            except:
                print("Failed to create folder: ", folderName)
                continue
    for folderName in existed:
        if (folderName != "github"):
            folders.pop(folderName)
    for folder in created:
        if len(folders[folder]) <= 3:
            for func in folders[folder]:
                folders.setdefault("uncategorized",[]).append(func)
            folders.pop(folder)
            func_dir.rmdir(folder)


def populate_folders():
    for folderName in folders:
        if not func_dir.isdir(folderName):
            print("Error: %s folder didn't exist, recreating...", folderName)
            try:
                func_dir.mkdir(folderName)
            except:
                print("Couldn't create folder: " + folderName)
        list_of_funcs = folders[folderName]
        for func in list_of_funcs:
            try:
                func_dir.rename(func, folderName+"/"+func)
            except:
                print("Failed to move function:", func)


def nest_standard_packages():
    common_packages = ["archive", "bufio", "builtin", "bytes", "compress", "container", "context", "crypto", "database", "debug", "embed", "encoding", "errors", "flag", "fmt", "go", "hash", "html", "image", "index", "io", "log", "math", "mime", "net", "os", "path", "plugin", "regexp", "sort", "strconv", "strings", "sync", "syscall", "testing", "text", "time", "unicode", "unsafe", "internal", "reflect", "vendor", "golang", "runtime", "type", "setg", "pthread", "walk", "gosave", "x", "cgo"]
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


def github_sort():
    if "github" in folders.keys():
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


create_folders()
populate_folders()
nest_standard_packages()
github_sort()

#Still need to handle a few stragglers from the conflicting sorting mechanism introduced in IDA 7.7 but this is much better :)
