import os
import subprocess
import IPython
import argparse
import tempfile
import re
import shutil
import time
import random
import copy
import pickle

# path to idat binary

IDA_DEFAULT_PATH=os.environ['HOME']+"/seclab_ida/ida/idat"
if os.environ['IDA_BASE_DIR']:
    IDA_PATH=os.environ['IDA_BASE_DIR']+"/idat"
else:
    IDA_PATH=IDA_DEFAULT_PATH


# path to defs.h
DEFS_PATH=os.path.dirname(os.path.realpath(__file__))+"/refs/defs.h"

# sometimes localization tools use stdio, so let's make sure that if any symbol from this library gets remapped to avoid collision
CSTDIO_FUNCS=[
    'clearerr', 'fclose', 'fdopen', 'feof', 'ferror', 'fflush', 'fgetc', 'fgetpos', 'fgets',
    'fileno', 'fopen', 'fprintf', 'fpurge', 'fputc', 'fputs', 'fread', 'freopen', 'fscanf', 'fseek',
    'fsetpos', 'ftell', 'fwrite', 'getc', 'getchar', 'gets', 'getw', 'mktemp', 'perror', 'printf',
    'putc', 'putchar', 'puts', 'putw', 'remove', 'rewind', 'scanf', 'setbuf', 'setbuffer', 'setlinebuf',
    'setvbuf', 'sprintf', 'sscanf', 'strerror', 'sys_errlist', 'sys_nerr', 'tempnam', 'tmpfile', 'tmpnam',
    'ungetc', 'vfprintf', 'vfscanf', 'vprintf', 'vscanf', 'vsprintf', 'vsscanf'
]

CSTDIO_DATASYMS=[
    'stderr','stdout','stdin'
]

VALIST_FUNCS=[
    'printf','fprintf','sprintf','scanf','sscanf','fscanf'
]
VALIST_TRANSFORM={x:f"v{x}" for x in VALIST_FUNCS}
GLIBC_XFORM_PREFIX="x__"

STUB_PREFIX="z__"

# not sure if all these are problematic types
#  these are types that included with "stdio.h"=>types.h
CHDR_TYPES=[
'gid_t', 'uid_t', 'pid_t', 
'id_t', 'blkcnt_t', 'blksize_t', 'caddr_t', 'clock_t', 
'clockid_t', 'daddr_t', 'fsblkcnt_t', 'fsfilcnt_t', 'mode_t',
'key_t', 'ino_t', 'nlink_t', 
'timer_t', 'suseconds_t', 'useconds_t', 'dev_t',
'time_t', 'off_t', 'loff_t', 'off64_t', 'socklen_t', '__va_list', 'ssize_t',
'uint_t', 'uint', 'u_char', 'u_short', 'u_int', 'u_long', 'u_int32_t', 'u_int16_t',
'u_int8_t', 'u_int64_t', 'ptrdiff_t', 'size_t', 'wchar_t', 'mode_t'
] 
# '__mode_t', '__ino_t', '__key_t', '__nlink_t', '__timer_t', '__suseconds_t', '__useconds_t', '__clockid_t',
#'__gid_t', '__uid_t', '__pid_t', '__id_t',
TYPES_REQUIRING_STDIO=['FILE']

DIETLIBC_TYPES=[
    'uint32_t','int32_t','uint8_t','int8_t','uint16_t','int16_t','bool'
]

STD_HEADER_TYPES=TYPES_REQUIRING_STDIO+CHDR_TYPES+DIETLIBC_TYPES

"""
# i know these are problematic types
CHDR_TYPES=[
    'time_t', 'off_t', 'mode_t'
]
"""
CHECK_DEF_start="#if (!defined(_SYS_TYPES_H) && !defined(_STDDEF_H)) \n"+\
"#define DONT_USE_LOCAL\n#endif\n"
_DEF_start="#ifndef DONT_USE_LOCAL"
_DEF_end="#endif"


# stub markers for processing

IDA_STUB_START = "// Function declarations"
IDA_DATA_START = "// Data declarations"
IDA_DECOMP_START = "//----- ("
IDA_SECTION_END = "//-----"
IDA_WEAK_LABEL = "; weak"

IDA_FUNC_WEAK_LABEL = "// weak"

TYPEDEF_START = "============================== START =============================="
TYPEDEF_END = "============================== END =============================="

# tags for primitives for replacement

DEBUG=False
def dprint(*args,**kwargs):
    if DEBUG:
        print(*args,**kwargs)


def get_primitives():
    basic_types=["float","double","long double","void"]
    basic_bintypes=["int","char","short","short int","long","long long","long int"]
    for x in basic_bintypes:
        basic_types.extend([f"{a}{x}" for a in ["", "unsigned ", "signed "]])
    return basic_types

PRIMITIVES = get_primitives()
            #["int", "long", "short", "char", "void", "double", "float", "long",
            #  "unsigned int", "unsigned long", "unsigned short", "unsigned char", "void", "long double"]


SYSTEM_TYPES=PRIMITIVES+STD_HEADER_TYPES

def get_basetype_info(field):
    # maybe this is a function prototype where there's only the type for each param
    # making this the default
    xtype=field.strip()
    # else, let's split on spaces as long as it's not the pointer corner case for function prototype
    if ':' in xtype:
        x=xtype.rsplit(':',1)[0].strip()
        xtype=x
    
    xtype=re.sub(r"\b(volatile|const)\b","",xtype).strip()
    ptr=xtype.endswith(' *')
    postfix=""
    if ptr:
        x=xtype.rsplit(' ',1)
        xtype,postfix=x[0],x[1]
    if ((xtype not in PRIMITIVES) and (' ' in xtype)):
        x=xtype.rsplit(' ',1)
        xtype=x[0].strip()
        xname=x[1].strip()
    return xtype+postfix

def cleanup_basetype(ptyp):
    ptyp_=ptyp.strip()
    while ptyp_.endswith('*') or ptyp_.endswith('('):
        ptyp_=ptyp_[:-1].rstrip()
    if ptyp_.startswith('const '):
        ptyp_=ptyp_[len('const '):]
    elif ptyp_.startswith('struct '):
        ptyp_=ptyp_[len('struct '):]
    elif ptyp_.startswith('union '):
        ptyp_=ptyp_[len('union '):]
    return ptyp_.strip()

def update_dependencies(orig_set:set,new_set:set):
    x=orig_set | new_set
    new_dependencies=False if x == orig_set else True
    
    return new_dependencies, x

def writepickle(pkl_file,data):
    if not os.path.exists(os.path.dirname(pkl_file)):
        os.makedirs(os.path.dirname(pkl_file))
    f=open(pkl_file,'wb')
    if data is not None:
        pickle.dump(data,f)
    f.close()

def readpickle(pkl_file):
    f=open(pkl_file,'rb')
    return pickle.load(f)

def is_function_ptr(line):
    #x=re.match("\s*\*?(\((\s*\*)+\s*\w+\)|\w+)\((.*)\)",line)
    #           return type            (*fn_name) fn_name (params) params
    #           1                      3          4       5        6
    line=line.strip()
    x=re.match("(\S+(\s+[^(]+)*\s*\**)\s*(\(\*\s*([^(]+)\))\s*(\((.*)\))$",line)
    
    is_fnptr=False
    rettype,fnptr_name,params,fn_no_params=(None,None,None,None)
    if x:
        is_fnptr=True
        rettype=x.group(1)
        fnptr_name=x.group(4)
        params=x.group(6)
        fn_no_params=f"{x.group(1)} {x.group(3)}"
    else:
        #            return type              *fn            fn       fn_p
        #            1                        3              4        5
        y=re.match("(\S+(\s+[^(]+)*\s*\**)\s*(\(\*\s*\(\*\s*([^()]+)\)(.*)\)\))\s*(\((void)\))$",line)
        if y:
            is_fnptr=True
            rettype=y.group(1)
            fnptr_name=y.group(4)
            params=y.group(5)
            fn_no_params=f"{y.group(1)} {y.group(3)}"

    return is_fnptr,rettype,fnptr_name,params,fn_no_params
        


def strip_binary(binary,out=None):
    import subprocess
    b_out=out
    if not out:
        b_out=f"{binary}.strip"
    x=subprocess.run(f"cp {binary} {b_out}",shell=True)
    if x.returncode!=0:
        print(f"[WARNING!] Failed to create {b_out} from binary source.\nSkipping stripping of symbols")
        b_out=binary
    else:
        x=subprocess.run(f"/usr/bin/strip --strip-all {b_out}",shell=True)
        if x.returncode!=0:
            print(f"[WARNING!] Failed to strip symbols from {b_out}!")
            print(f"Reverting to original binary")
            b_out=binary
    return b_out


class IDAWrapper:
    def __init__(self, typedefScriptPath):
        self.typedefScriptPath = typedefScriptPath

    # get initial decompiled output of ida hexrays
    def decompile_func(self, binary_path, func:str, decompdir:str):
        outname = "/tmp/"+func.strip()+f"{int(random.getrandbits(16))}"
        decompf=f"{decompdir}/{func.strip()}.c"
        #for func_name in func_list:
        #    funcs += func_name.strip() + ":"
        #funcs = funcs[:-1] #trim dangling ':'

        # ida run command
        functionLines = ""
        if not os.path.exists(decompf) or (os.stat(decompf).st_size==0):
            ida_command = [IDA_PATH, "-Ohexrays:-nosave:"+outname+":"+func, "-A", binary_path]
            print("Running: ", " ".join(ida_command),flush=True)
            subprocess.run(ida_command)
            
    
            if not os.path.exists(outname+".c"):
                print("    !!! ERROR DECOMPILING FILE", outname+".c")
                return ""
    
            with open(f"{outname}.c", "r") as decompFile:
                functionLines = decompFile.read()
            decompFile.close()
            shutil.copyfile(f"{outname}.c",decompf)
            os.remove(f"{outname}.c")
            print("[COMPLETED] Running: ", " ".join(ida_command))
        else:
            with open(decompf, "r") as decompFile:
                functionLines = decompFile.read()
                decompFile.close()


        return functionLines
    # get initial decompiled output of ida hexrays
    def decompile(self, binary_path, func_list:list):
        if len(func_list) <= 0:
            print("Empty List of Functions!!")
            return ""

        outname = "/tmp/"+func_list[0].strip()
        funcs = ""
        for func_name in func_list:
            funcs += func_name.strip() + ":"
        funcs = funcs[:-1] #trim dangling ':'

        # ida run command
        ida_command = [IDA_PATH, "-Ohexrays:-nosave:"+outname+":"+funcs, "-A", binary_path]
        print("Running: ", " ".join(ida_command))
        subprocess.run(ida_command)

        functionLines = ""
        if not os.path.exists(outname+".c"):
            print("    !!! ERROR DECOMPILING FILE", outname+".c")
            return ""

        with open(outname+".c", "r") as decompFile:
            functionLines = decompFile.read()
        decompFile.close()
        os.remove(outname+".c")

        return functionLines

    # # given a decompiled ida string, find all func calls in that string

    # get all typedef mappings
    def get_typedef_mappings(self, binary_path,output,use_new_features=False):
        typedefMap = dict()
        typedef_f=f"{output}/typedefs.h"
        typedefs=None
        if not os.path.exists(typedef_f) or (os.stat(typedef_f).st_size==0):
            ida_command = [IDA_PATH, '-B', '-S'+"\""+self.typedefScriptPath+"\"", "-A", binary_path]
            tmpName = ""
            # getting rid of tempfile since I'm saving the original typedef info to a file anyway
            #with tempfile.NamedTemporaryFile(mode="r", dir="/tmp", prefix="prd-ida-",delete=True) as tmpFile:
            with open(typedef_f,"w") as tmpFile:
                print("RUNNING: ", " ".join(ida_command),flush=True)
                env = os.environ
                env['IDALOG'] = os.path.realpath(typedef_f)
                sp = subprocess.run(ida_command, env=env)

                tmpFile.close()
        
        
        with open(typedef_f,"r") as tmpFile:
            typedefs = tmpFile.read()
            tmpFile.close()
            
        structDump = ""
        latch = False
        for line in typedefs.splitlines():
            if TYPEDEF_START in line:
                latch = True
            elif TYPEDEF_END in line:
                latch = False
            elif latch:
                if "/*" in line and "*/" in line:
                    structDump += "\n"
                    continue
                if line.startswith("#define") and use_new_features:
                    structDump += "\n"
                structDump += line

        print("FINISHED RUNNING",flush=True)
        return structDump


class CodeCleaner:
    def __init__(self):
        self.weakFuncs = []

    def getTypeAndLabel(self, header, fn_ptr=False):
        array,hType,hLabel=(None,None,None)
        
        if ")" in header and "((aligned(" not in header and "()" not in header and not fn_ptr:
            array = header.rsplit(")", maxsplit=1)
            hType = array[0].strip()+")"

        elif fn_ptr:
            hType = "void *"
            func_ptr_name=re.match("(\w+\s+)+\(\s*\*+\s*(\w+)\)",header)
            if func_ptr_name:
                dprint("DEBUG : getTypeAndLabel {} => {}".format(header,func_ptr_name.group(2)))
                return hType,func_ptr_name.group(2)
            func_ptr_name=re.match("(\w+\s+)+\*\s*\(\s*\*+\s*(\w+)\)",header)
            if func_ptr_name:
                dprint("DEBUG : getTypeAndLabel {} => {}".format(header,func_ptr_name.group(2)))
                return hType,func_ptr_name.group(2)
            else:
                dprint("FAILURE : getTypeAndLabel {} ".format(header))
                assert(False)
        else:
            array = header.rsplit(maxsplit=1)
            hType = array[0].strip()

        if len(array) > 1:
            hLabel = array[1].strip()
        else:
            hLabel = ""

        hLabel = hLabel.strip("()")
        while hLabel.startswith("*"):
            hType = hType + " *"
            hLabel = hLabel[1:]

        if "__stdcall" in hType:
            hType = hType.replace("__stdcall", "")

        hLabel = hLabel.strip(";")

        return hType, hLabel

    def is_basic_typedef(self, line):
        if not line.startswith("typedef"):
            return False
        if line.startswith("typedef struct"):
            return False
        if line.startswith("typedef union"):
            return False

        if "(" in line or "{" in line:
            return False
        return True

    def get_type_label(self,argTypeRaw):
        argType = self.get_typebase(argTypeRaw)
        argTypeArray = argType.strip().rsplit(maxsplit=1)
        if len(argTypeArray) > 1:
            argTypeLabel = argTypeArray[-1]
        else:
            argTypeLabel = argTypeArray[0]
        return argTypeLabel
    

        
    def check_func_prototype(self,input_):
        return re.match("((struct\s+)?\w+)\s+\*?(\((\s*\*)+\s*\w+\)|\w+)\((.*)\)",input_)

    def is_function_prototype(self,argType):
        func=self.check_func_prototype(argType)
        types=[]
        ret=False
        if func:
            dprint("Function: "+argType)
            types.append(self.get_type_label(func.group(1)))
            x=re.split(r',',func.group(4))
            for t in x:
                types.append(self.get_type_label(t))
            ret=True
        return ret,types


    def get_typebase(self, argType):
        argType = argType.strip()

        while argType.endswith("*") or argType.startswith("*"):
            argType= argType.strip("*")
            argType = argType.strip()

        return argType

    def get_struct_args(self, argString):
        argString = argString.strip()
        args = argString.split(";")
        argList = []
        for arg in args:
            arg = arg.split(":")[0]
            arg = arg.strip()
            if arg:
                argType, argName = self.getTypeAndLabel(arg)
                argList.append((argType, argName, arg))
        return argList

    # seperate each ordinal, filter out cases, establish bindings
    def typedef_firstpass(self, structDump):
        dprint("    > RUNNING FIRSTPASS")
        lineDump = ""

        for line in structDump.splitlines():
            if "{" not in line and "}" not in line:
                if line.count(";") > 1:
                    line = line.strip()
                    line = line.replace(";", ";\n")
            lineDump += line+"\n"
        return lineDump

    def typedef_remove_errata(self,structDump):
        lineDump=""
        for line in structDump.splitlines():
            if "Elf" in line:
                continue #skip
            elif line.startswith("decls:"):
                continue
            elif len(line.strip())==0:
                continue
            lineDump += line+"\n"

        return lineDump        



    def typedef_secondpass(self, structDump):
        dprint("    > RUNNING SECOND PASS")
        lineDump = ""
        typedefMap = {}
        structMap = {}
        substituteMap = {}



        for line in structDump.splitlines():
            if "Elf" in line:
                continue #skip
        
            if line.startswith("typedef"):
                elements = line.strip()[8:] #strip typedef + space
                array = elements.split("(", maxsplit=1)
                orig = ""
                if len(array) > 1:
                    orig = array[0].strip()
                    newVal = "("+array[1].strip().strip(";")
                else:
                    array = array[0].rsplit(maxsplit=1)
                    orig = array[0].strip()
                    newVal = array[1].strip().strip(";")

                dprint("  << read line ", line)
                typedefMap[orig] = (newVal, line)
            elif line.startswith("struct ") or line.startswith("union "):
                elements = line.strip().split(maxsplit=1)
                header = elements[0].strip()
                array = elements[1].split("{", maxsplit=1)
                structDec = header+" "+array[0].strip()
                structName = structDec.rsplit(maxsplit=1)[1]
                dprint("  << read struct [%s] == %s" % (structName, structDec))
                structMap[structName] = structDec
                if structDec not in typedefMap.keys():
                    typedefMap[structDec] = (structName, line)

        for line in structDump.splitlines():
            if "Elf" in line:
                continue #skip

            if line.strip():
                dprint("  !! Processing line ", line)
                done = set()
                for origName, typedefTuple in typedefMap.items():
                    if not line.startswith("typedef "+origName) and \
                       ("{" in line or "(" in line): # found struct defines
                        # substitute typedefs with their original value
                        # this is so we can move the struct to before the typedefs themselves
                        if "{" in line:
                            argLine = "{"+line.split("{", maxsplit=1)[1]
                        else:                            
                            argLine = "("+line.split("(", maxsplit=1)[1]

                        newVal = typedefTuple[0]
                            

                        dprint("   - Check for use of %s, originally [%s]" % (newVal, origName))
                        typedefLine = typedefTuple[1]
                        escapedNewVal = re.escape(newVal)
                        matches = re.findall("[\\(\\{\\)\\}\\;\\,][\s]*"+escapedNewVal+"[\\(\\{\\)\\}\\;\\,\s]+", argLine)
                        for match in matches:
                            if origName in structMap.keys():
                                origName = structMap[origName]
                            if origName not in done:
                                newLine = match.replace(newVal, origName)
                                line = line.replace(match, newLine)

                        if matches:
                            dprint("      Associating %s with %s" % (typedefLine, line))
                            done.add(origName)
                            # substituteMap[typedefLine] = line
                        # break

            lineDump += line+"\n"
        return lineDump


    def typedef_lastpass(self, structDump):
        definitions = ""
        for line in structDump.splitlines():
                defLine = ""

                if line.startswith("typedef"):
                    defLine = line

                elif line.startswith("union"):
                    array = line.split("{")
                    name = array[0].split()[1].strip()
                    elems = array[1].strip().strip(";")
                    defLine = "typedef " + array[0] + "{" + elems + " " + name + ";\n"

                elif line.startswith("enum"):
                    array = line.split("{")
                    header = array[0].split(":")[0].strip()
                    name = header.split()[1].strip()
                    enums = array[1]

                    enumLine = header + "{" + enums
                    typeDefLine = "typedef " + header + " " + name + ";"
                    defLine = enumLine + "\n" + typeDefLine

                elif line.startswith("struct"):

                    line = line.strip(";") # prune out ending semicolon
                    header = line.split("{")[0].strip()
                    typeName = header.rsplit(maxsplit=1)[1].strip() # get name, drop struct prefixes

                    
                    matches = re.findall("[\\(\\{\\;][\s]*"+typeName+" ", line)
                    for match in matches:
                        newLine = match.replace(typeName, header)
                        line = line.replace(match, newLine)
                    defLine = "typedef "+line+" "+typeName+";"


                definitions += defLine+"\n"
        return definitions

    def process_one_defline(self, definitions, line, waitingStructs, defined, forward_declared, typeDefMap):
        dprint("   CHECKING: ", line)

        rearranged = False
        resolved = True

        defline = line.strip(";") # prune out ending semicolon
        # get rid of attributes, we don't care
        defline,num = re.subn(r"__attribute__\(\(\w+(\(\w+\))?\)\)",r"",defline)
        argString = ""
        typedef_decl=False

        if "{" in line or "(" in line:
            array = defline.split("{")
            header = array[0].strip()
            f = header.rsplit(maxsplit=1) 
            struct_or_union = f[0].strip() # get struct_or_union
            typeName = f[1].strip() # get name, drop struct prefixes

            if line.startswith("typedef struct") or line.startswith("typedef union") :
                body = array[1].strip()
                argString = body.split("}")[0]
                typedef_decl=True
            else:
                array = defline.split(")", maxsplit=1)
                header = array[0].split("(")[1].strip()
                typeName = header
                body = array[1].strip()
                args = body.split(")", maxsplit=1)[0].strip().strip("(")
                argsArray = args.split(",")
                argsArray.append("")
                argString = " dummy;".join(argsArray)

        elif line.startswith("typedef "):
            array = defline.rsplit(maxsplit=1)
            header = array[0]
            simpleType = header.split(maxsplit=1)[1] #trim typedef
            argString = simpleType+" dummy" # add dummy
            typeName = array[1]
            typeDefMap[self.get_typebase(typeName)] = simpleType

        typeName = self.get_typebase(typeName)

        if typeName in defined:
            dprint("    - Already Processed!")
            return definitions, rearranged

        if argString:
            args = self.get_struct_args(argString)
            for argTypeRaw, argName, argOrig in args:
                isfunc,type_labels = self.is_function_prototype(argTypeRaw)
                if not isfunc:
                    argType = self.get_typebase(argTypeRaw)
                    argTypeArray = argType.strip().rsplit(maxsplit=1)
                    
                    if len(argTypeArray) > 1:
                        type_labels = [ argTypeArray[-1] ]
                    else:
                        type_labels = [ argTypeArray[0] ]
                    
                for argTypeLabel in type_labels:
                    if argTypeLabel == typeName:
                        continue # skip self references
                    if argTypeLabel not in PRIMITIVES and argTypeLabel not in defined:
                        if not(argTypeLabel in forward_declared and \
                               (not self.is_basic_typedef(line))): # move non-struct non-union typedefs

                            if argTypeLabel not in waitingStructs.keys():
                                waitingStructs[argTypeLabel] = []
                            waitingStructs[argTypeLabel].append((line, argTypeLabel, argTypeRaw))
                            rearranged = True
                            resolved = False
                            dprint("    --> unresolved type", argTypeLabel)
                            dprint("         ", forward_declared, (argTypeLabel in forward_declared))
                            dprint("        %s || %s" % (line, argTypeRaw))
                            # dprint("        defined: ", defined)


        if resolved:
            dprint("    !! DEFINED", typeName)
            defined.append(typeName)
            definitions += line+"\n"

            if typeName in waitingStructs.keys():
                dprint("   !--> RESOLVING: ", typeName)
                lines = waitingStructs[typeName]
                waitingStructs.pop(typeName)
                for line, argTypeLabel, argTypeRaw in lines:
                    dprint("    - Recursive process", typeName)
                    definitions, child_rearranged = self.process_one_defline(definitions, line, waitingStructs, defined, forward_declared, typeDefMap)
                    if not resolved or child_rearranged:
                        rearranged = True
                dprint("        - RESOLVED!", typeName)
        else:
            rearranged = True

        return definitions, rearranged

    def recursive_dep_check(self, typeDefMap, waitingStructs, key):
        if key in waitingStructs.keys():
            return True
        elif key in typeDefMap.keys():
            newKey = typeDefMap[key]
            dprint("   ## Recursing", key, "->", newKey)
            return self.recursive_dep_check(typeDefMap, waitingStructs, newKey)
        return False

    def resolve_defs(self, structDump):
        definitions = ""
        defined= []
        forward_declared = []
        waitingStructs = {}
        typeDefMap = {}
        rearranged = False
        for line in structDump.splitlines():
            if line.startswith("typedef"):
                definitions, child_rearranged = self.process_one_defline(definitions, line, waitingStructs, defined, forward_declared, typeDefMap)
                if child_rearranged:
                    rearranged = True
            elif line.startswith("struct"):
                # forward declaration
                typeName = line.strip().strip(";").rsplit(maxsplit=1)[1];
                dprint("    !! FORWARD DECLARATION - STRUCT", typeName)
                definitions += "struct "+typeName+";\n"
                forward_declared.append(typeName)
            elif line.startswith("union"):
                # forward declaration
                typeName = line.strip().strip(";").rsplit(maxsplit=1)[1];
                dprint("    !! FORWARD DECLARATION - UNION", typeName)
                forward_declared.append(typeName)
                definitions += "union "+typeName+";\n"
            else:
                definitions += line+"\n"

        remainingLines = []
        potentialPlaceholders = set()
        rejectedPlaceholders = set()
        for needed, lines in waitingStructs.items():
            for line, argTypeLabel, argTypeRaw in lines:
                if line not in remainingLines:
                    remainingLines.append(line)
                    if not self.is_basic_typedef(line):
                        array = line.split("{")
                        header = array[0].strip()
                        f=header.rsplit(maxsplit=1) # get name, drop struct prefixes
                        struct_or_union = f[0].strip() # get name, drop struct prefixes
                        typeName = f[1].strip() # get name, drop struct prefixes
                       
                        dprint("EVALUTING [%s] as Placeholder!" % typeName)
                        dprint("  ==", argTypeRaw)
                        dprint("  == ", (self.recursive_dep_check(typeDefMap, waitingStructs, typeName)))
                        dprint("  ==", (typeName not in rejectedPlaceholders))
                        if self.recursive_dep_check(typeDefMap, waitingStructs, typeName) and typeName not in rejectedPlaceholders:
                            if "union" in struct_or_union:
                                potentialPlaceholders.add("union "+typeName)
                            else:
                                potentialPlaceholders.add(typeName)
                        # if any of the waitingStructs use the needed placeholder without a pointer, reject this placeholder
                        if  "*" not in argTypeRaw:
                            dprint("removing ", argTypeLabel, "as placeholder. argTypeLabel", argTypeLabel)
                            dprint("    line: ", line)
                            if argTypeLabel in potentialPlaceholders:
                                potentialPlaceholders.remove(argTypeLabel)
                            rejectedPlaceholders.add(argTypeLabel)

        for placeholder in potentialPlaceholders:
            # create placeholder forward declaration
            if placeholder not in forward_declared:
                if "union" in placeholder:
                    dprint("Adding Placeholder ", placeholder)
                    definitions += placeholder+";\n"
                else:
                    dprint("Adding Placeholder Struct ", placeholder)
                    definitions += "struct "+placeholder+";\n"

        for line in remainingLines:
            definitions += line+"\n"
            rearranged = True

        return definitions, rearranged

    def rearrange_typedefs(self, structDump):
        MAXTRIES = len(structDump.splitlines())
        rearranged = True
        definitions = structDump
        tries = 0

        while tries < MAXTRIES and rearranged:
            passCount = " Reordering typedefs [Pass %d] " % (tries+1)
            print(("-"*5) + passCount + ("-"*5))
            definitions, rearranged = self.resolve_defs(definitions)
            tries += 1
            print(("-"*10) + " Rearranged: " + str(rearranged) + " " + ("-"*10))

        if tries >= MAXTRIES:
            print("    !! ERROR !! Unable to resolve typedef order")

        return definitions


    def resolve_type_order(self, structDump,output):
        typedef_f=f"{output}/resolved-typedefs.h"
        rectype_f=f"{output}/recovered-types.txt"
        recovered_types=None
        needs_stdio=False
        if os.path.exists(typedef_f):
            with open(typedef_f,'r') as typedefh:
                structDump=typedefh.read()
                typedefh.close()
            with open(rectype_f,'r') as rtypefh:
                r=[x.strip() for x in rtypefh.readlines()]
                needs_stdio=True if r[0]=="True" else False
                recovered_types=r[1:]
                rtypefh.close()
        else:
            structDump = self.typedef_firstpass(structDump)
            structDump = self.typedef_remove_errata(structDump)
            structDump,recovered_types,needs_stdio = self.typedef_resolution(structDump)
            with open(typedef_f,"w") as typedfh:
                typedfh.write(structDump)
                typedfh.close()
            with open(rectype_f,"w") as rtypefh:
                rtypefh.write(f"{needs_stdio}\n")
                rtypefh.write("\n".join(recovered_types))
                rtypefh.close()
        return structDump,recovered_types,needs_stdio
    
    def update_params_for_typeclass(self,line,forward_decls,enum_decls):
        isfnptr,fnrettype,fnptrname,fnptrparams,fnptr_no_params=is_function_ptr(line)
        fwddecls_used=list()
        enumdecls_used=list()
        if isfnptr:
            bt=cleanup_basetype(fnrettype)
            if forward_decls.get(bt,None) is not None:
                fnptr_no_params="struct "+fnptr_no_params
            params_=[fnptrparams.strip()]
            if ',' in fnptrparams:
                params_=fnptrparams.strip().split(',') # parans should have been removed 
            if len(params_)>0 or not (len(params_)==1 and params_[0].strip()==""):
                for i,p in enumerate(params_):
                    p=p.strip()
                    bt=get_basetype_info(p)
                    xt=cleanup_basetype(bt)
                    xlu=forward_decls.get(xt,None)
                    xlu_enum=enum_decls.get(xt,None)
                    if xlu is not None:
                        if xt not in fwddecls_used:
                            fwddecls_used.append(xt)
                        if not p.startswith('const '):
                            params_[i]=f"struct {p}"
                        else:
                            params_[i]=f"const struct {p[len('const '):]}"
                    elif xlu_enum is not None:
                        if xt not in enumdecls_used:
                            enumdecls_used.append(xt)
                        if not p.startswith('const '):
                            params_[i]=f"enum {p}"
                        else:
                            params_[i]=f"const enum {p[len('const '):]}"
                new_params=",".join(params_)
                return True,new_params,fnptr_no_params,fwddecls_used,enumdecls_used
        
        return False,None,None,fwddecls_used,enumdecls_used

    def typedef_resolution(self,structDump):
        type_lines=structDump.splitlines()
        
        
        
        DEFINED=set()
        # default dict for each defined type/construct
        # once all 'reqs' types are defined, then satisfied=True and we can write out the line to file
        type_info={
            'storage':None,
            'defalloc':None,
            'deftype':None,
            'base_type':None,
            'defname':None,
            'reqs':None,
            'line':None,
        }
        simple_types=list()
        collective_types=list()
        fnptr_types=list()
        aliased_types=dict()

        
        forward_decls=dict()
        enum_decls=dict()
        pound_defines=dict()
        
        fwd_decl_types=set()
        enum_types=set()
        define_later=set()
        pnddef=list()
        appearance_order=list()


        # this maps all types to any dependent declaration
        type_to_dependencies=dict()
        define_=re.compile(r"^#define\s+(\w+)\s+(.*$)")
        fwd_=re.compile(r"^\s*(struct|union)\s+(\S+)\s*;\s*$")
        enum_=re.compile(r"^\s*(enum)\s+(\S+)\s*:\s*(\S+)(\{(.*)\})\s*;\s*$")
        simple=re.compile(r"^\s*typedef\s+((const\s+|struct\s+|union\s+)?((long\s+|short\s+|unsigned\s+|signed\s+)*\S+)\s+\*?)(\S+.*)\s*;\s*$")
        struct_union=re.compile(r"^\s*((struct|union)(\s+__attribute__\(\(.*\)\))?)\s+(\S+)\s*(\{\s*(.*)\s*\}\s*);\s*$")
        typ_st_un=re.compile(r"^\s*typedef\s+(struct|union)\s+(\S+)\s*(\{\s*(.*)\s*\}\s*)(\S+)\s*;\s*$")
        typ_fnptr=re.compile(r"^\s*typedef\s+((([^(\s]+\s+)+([^(\s]+\s+)*(\*+)?)(\(\s*\*\s*([^(]+)\))\s*(\((.*)\)))\s*;\s*$")
        # ORIG: typ_fnptr=re.compile(r"^\s*typedef\s+((\S+(\s+[^(]+)*\s*\**)\s+(\(\s*\*\s*([^(]+)\))\s*(\((.*)\)))\s*;\s*$")
        # TESTING:typ_fnptr=re.compile(r"^\s*typedef\s+((\S+(\s+[^(]+)*(\s*\*)*)\s+(\(\s*\*\s*([^(]+)\))\s*(\((.*)\)))\s*;\s*$")
        # WORKS: typ_fnptr=re.compile(r"^\s*typedef\s+((\S+(\s+[^(]+)*\s*\**)\s*(\(\s*\*\s*([^(]+)\))\s*(\((.*)\)))\s*;\s*$")
        #typedef const sqlite3_io_methods_0 *(*finder_type)(const char *, unixFile_0 *);
        #typ_fnptr=re.compile(r"^\s*typedef\s+(((const\s+|unsigned\s+|signed\s+)?(long\s+|short\s+)?(\s+[^(]+)*\s*\**)\s+(\(\s*\*\s*([^(]+)\))\s*(\((.*)\))))\s*;\s*$")
        pnddef_re=None
        for t in type_lines:

            _ltype=None
            t=t.strip()

            t=re.sub("\s\s"," ",t)
            is_define=re.match(define_,t)
            
            if not is_define and pnddef_re:
                # if a #define is being used at all, let's substitute it for the actual value before moving on
                m=pnddef_re.search(t)
                cnt=0
                while m:
                    pval=m.group(1).strip()
                    newval=re.match(define_,pound_defines[pval]).group(2).strip()
                    t=re.sub(r"\b"+pval+r"\b",newval,t)
                    m=pnddef_re.search(t)
                    cnt+=1
                if cnt>0:
                    dprint(f"!!! UPDATED LINE : {t}",flush=True)

            is_forward_decl = re.match(fwd_,t)
            # need 1 2 4
            is_enum = re.match(enum_,t)
            #                                             deftype        alias
            # GROUP                                       1                5
            is_simple_typedef = simple.match(t)
            #                                    stype            name   fields
            # GROUP                              2                4      6
            is_struct_or_union = re.match(struct_union,t)
            # GROUP                              1                2      4                  5 (name)                   
            is_typedef_struct_or_union = re.match(typ_st_un,t)
            #                                             return_type      fn_ptr_name        params
            # GROUP                                       2                6                  9
            is_fnptr_typedef = re.match(typ_fnptr,t)
            #x=re.match("(\S+(\s+[^(]+)*\s*\**)\s*(\(\*\s*([^(]+)\))\s*(\((.*)\))$",line)
            if is_define:
                alias=is_define.group(1).strip()
                pound_defines[alias]=t
                dprint(f"FOUND Early Declaration: '{alias}'")
                pnddef.append(alias)
                pnddef_re=re.compile(r"\b("+"|".join(pnddef)+r")\b")
                #DEFINED.append(alias)
            elif is_forward_decl:
                #forward_decls.append(t)
                ftype=is_forward_decl.group(1).strip()
                alias=is_forward_decl.group(2).strip()
                forward_decls[alias]={'line':t,'storage':ftype}
                fwd_decl_types.add(alias)
                dprint(f"FOUND FWD Declaration: '{alias}' <= '{t}")
            elif is_enum:
                etype=is_enum.group(3).strip()
                ename=is_enum.group(2).strip()
                eprefix=is_enum.group(1).strip()
                efields=is_enum.group(4).strip()
                # need 1 2 4
                et = f"{eprefix} {ename} {efields};"
                if etype in SYSTEM_TYPES or etype in pnddef:
                    #pnddef.append(ename)
                    #enum_types.add(ename)
                    enum_decls[ename]=et
                    enum_types.add(ename)
                    dprint(f"FOUND DEFINE: '{ename}'")
                else:
                    dprint(f"ERROR: Can't readily resolve enumeration base type [{etype}]")
                    dprint(f"Just going to add it anyway")
                    #pnddef.append(et)
                    enum_decls[ename]=et
                    enum_types.add(ename)
                
            elif is_simple_typedef and (is_fnptr_typedef is None):
                
                _ltype=copy.copy(type_info)
                base_type=is_simple_typedef.group(1).strip()
                alias=is_simple_typedef.group(5).strip()
                req_type=cleanup_basetype(base_type).strip()
                if req_type=="":
                    req_type=None

                # if any struct or union is inlined with the typedef, capture it
                prefixes=['struct ','union ']
                inline_def=[base_type.startswith(prefix) for prefix in prefixes]
                
                if any(inline_def):
                    # ehhh, this is an implementation issue, in other types, struct or unions don't go into something like 'storage', but 'deftype'
                    # this should really be fixed
                    idx=inline_def.index(True)
                    _ltype['storage']=prefixes[idx].strip()
                    base_type=req_type
                elif base_type in enum_types:
                    t=re.sub(r"\btypedef\b",f"typedef enum",t)

                elif base_type in collective_types:
                    ref_line=type_to_dependencies[base_type]['line']
                    ref_stor=type_to_dependencies[base_type]['storage']
                    # we're prepending the type to make sure that 'struct' or 'union' prepends the base type name
                    if not re.search(r"\b"+ref_stor+r"\b",t):
                        t=re.sub(r"\btypedef\b",f"typedef {ref_stor}",t)

                _ltype['base_type']=req_type
                _ltype['deftype']=base_type
                _ltype['defname']=alias
                _ltype['reqs']=set([req_type])
                _ltype['line']=t
                if req_type not  in appearance_order:
                    appearance_order.append(req_type)
                appearance_order.append(alias)

                dprint(f"SIMPLE TYPEDEF: {t} [{base_type}] [{alias}] [{req_type}]")
                
                if type_to_dependencies.get(alias,None) is not None:
                    dprint(f"I constructed this => {_ltype}")
                    dprint(f"But this already existed => {type_to_dependencies[alias]}")
                    dprint(alias in simple_types)
                    dprint(alias in enum_types)
                    dprint(alias in fwd_decl_types)
                    dprint(alias in collective_types)
                    assert False
                type_to_dependencies[alias]=_ltype
                simple_types.append(alias)
                if aliased_types.get(req_type,None) is None:
                    aliased_types[req_type]=list()
                aliased_types[req_type].append(alias)
            elif is_struct_or_union or is_typedef_struct_or_union:
                _ltype=copy.copy(type_info)
                stype,name,fields,line_=(None,None,None,copy.copy(t))
                if is_struct_or_union:
                    stype=is_struct_or_union.group(2).strip()
                    name=is_struct_or_union.group(4).strip()
                    fields=is_struct_or_union.group(6).strip()
                    dprint(f"STRUCT OR UNION: {t} [stype='{stype}'][name='{name}'][fields='{fields}']",flush=True)
                    if line_.endswith(';'):
                        line_=line_[:-1]
                    line_=f"typedef {line_} {name};"
                    forward_decls[name]={'line':f"{stype} {name};",'storage':stype}
                    fwd_decl_types.add(name)
                elif is_typedef_struct_or_union:
                    stype=is_typedef_struct_or_union.group(1).strip()
                    name=is_typedef_struct_or_union.group(5).strip()
                    fields=is_typedef_struct_or_union.group(4).strip()
                    dprint(f"TYPEDEF STRUCT OR UNION: {t} [stype='{stype}'][name='{name}'][fields='{fields}']",flush=True)
                
                fields=fields[:-1] if fields.endswith(';') else fields
                reqs_=set()
                x_fields=fields.split(';')
                for xf in x_fields:
                    isfnptr,fnrettype,fnptrname,fnptrparams,fnptr_noparams=is_function_ptr(xf.strip())
                    if isfnptr:
                        fn_ret=cleanup_basetype(fnrettype)
                        dprint(f"FIELD [FNPTR]: {xf} [{fn_ret}] [{fnptrname}]")
                        reqs_.add(fn_ret)
                        params__=fnptrparams.strip().split('(') # parans should have been removed 
                        params_,params=([],[])
                        for p in params__:
                            params_.extend(p.strip().split(')'))
                        for p in params_:
                            params.extend(p.strip().split(','))
                        for p in params:
                            xt=get_basetype_info(p)
                            if ((xt!="**") or (len(xt)==0)):
                                dprint(f"FIELD [FNPTR] [PARAM]: {p} => {xt} => {cleanup_basetype(xt)}")
                                reqs_.add(cleanup_basetype(xt))
                    else:
                        xt=get_basetype_info(xf)
                        reqs_.add(cleanup_basetype(xt))
                        dprint(f"FIELD : '{xf}' => '{xt}' ({cleanup_basetype(xt)})")
                if "" in reqs_:
                    dprint(f"ISSUE WITH REQ (1): {name}")
                    reqs_.remove("")
                # this should actually be something like 'storage'
                _ltype['storage']=stype
                _ltype['deftype']=None
                _ltype['defname']=name
                _ltype['reqs']=set(reqs_)
                _ltype['line']=line_                
                assert type_to_dependencies.get(name,None)==None
                type_to_dependencies[name]=_ltype
                collective_types.append(name)
                for r in list(reqs_):
                    if r not in appearance_order:
                        appearance_order.append(r)
                appearance_order.append(name)
                if name in list(aliased_types.keys()):
                    dprint(f"NAME IS ALIASED ===> {name}")
                    valid_prefix=None
                    for prefix in ['struct ','union ']:
                        if (t.startswith(prefix)):
                            valid_prefix=prefix
                            break
                    if valid_prefix is not None:
                        for als in aliased_types[name]:
                            ref_line=type_to_dependencies[als]['line']
                        # should be on correct prefix
                            if(not ref_line.startswith("typedef "+valid_prefix)):
                                ref_line=re.sub(r"\btypedef\b",f"typedef {valid_prefix}",ref_line)
                                dprint(f"ALIAS UPDATE: Updating line to '{ref_line}'")
                    
                            type_to_dependencies[als]['line']=ref_line                    

                dprint(f"STRUCT OR UNION => DONE WITH '{name}' => {name in simple_types} or {name in list(fwd_decl_types)}")

            elif is_fnptr_typedef:
                
                isfnptr,fnrettype,fnptrname,fnptrparams,fnptr_noparams= \
                    is_function_ptr(is_fnptr_typedef.group(1).strip())
                _ltype=copy.copy(type_info)
                #ret_type=is_fnptr_typedef.group(2)
                #fn_name=is_fnptr_typedef.group(4)
                #params=is_fnptr_typedef.group(6)
                _ltype['deftype']=fnrettype
                _ltype['base_type']=cleanup_basetype(fnrettype)
                _ltype['defname']=fnptrname
                dprint(f"FNPTR TYPEDEF: {t} => {is_fnptr_typedef.group(1).strip()} => {fnrettype} => {fnptrname}")
                reqs_=set([cleanup_basetype(fnrettype)])
                params_=fnptrparams.strip().split(',') # parans should have been removed 
                for p in params_:
                    xt=get_basetype_info(p)
                    reqs_.add(cleanup_basetype(xt))
                if "" in reqs_:
                    dprint(f"ISSUE WITH REQ (2): {name}")
                    reqs_.remove("")
                _ltype['reqs']=set(reqs_)
                _ltype['line']=copy.copy(t)
                assert type_to_dependencies.get(fnptrname,None)==None
                type_to_dependencies[fnptrname]=_ltype
                fnptr_types.append(fnptrname)
                for r in list(reqs_):
                    if r not in appearance_order:
                        appearance_order.append(r)
                appearance_order.append(fnptrname)
            else:
                dprint(f"ERROR: the following line can't be parsed: \n>>\n'{t}'\n<<")
                dprint(is_simple_typedef)
                dprint(is_fnptr_typedef)
        
        # let's get rid of this processing error before it propagates
        for i in list(type_to_dependencies.keys()):
            reqs=type_to_dependencies[i]['reqs']
            ld=list(reqs)
            for j in ["...",""]:
                if j in ld:
                    reqs.remove(j)
            type_to_dependencies[i]['reqs']=reqs

        fwd_declared_no_type={d:forward_decls[d] for d in fwd_decl_types if (type_to_dependencies.get(d,None) is None)}
        

        """
        for k,v in fwd_declared_no_type.items():
            

            _ltype=copy.copy(type_info)
            _ltype['reqs']=set()
            _ltype['line']=v['line']
            _ltype['deftype']=v['storage']
            _ltype['defname']=k
            type_to_dependencies[k]=_ltype
        """

        DEFINED=set(pnddef)

        # list of defined or potentially defined types
        potdefined_types=list(set(list(type_to_dependencies.keys())+list(DEFINED)+list(enum_types)+fnptr_types+simple_types+SYSTEM_TYPES))
        missing_type_defs=[]
        
        
        # this loop allows to preprocess the types and their requirements to:
        #  1) get rid of extraction issues or "..." i.e., weird type results
        #  2) identify missing type definitions to prevent accumulating errors
        #  3) transform type definition lines to use the 'enum', 'struct', or 'union' keywords as appropriate
        #       which allows for forward declaration use in the case of circular references in type definitions
        #      => i.e., when another struct or a function pointer has a field that's a struct/union
        #               without 'struct|union' keyword, prepend it to the field
        #  4) similar to 3, but when a simple typedef references a enum, struct or union type without that keyword, prepend it
        for i in list(type_to_dependencies.keys()):
            line=type_to_dependencies[i]['line']
            reqs=type_to_dependencies[i]['reqs']
            
            fdecls=[d in fwd_decl_types for d in reqs]
            enumdecls=[d in enum_types for d in reqs]
            not_defined=[]
            for idx,d in enumerate(copy.copy(reqs)):
                # Reason #1
                if d in ["...",""]:
                    del req[idx]
                elif d not in potdefined_types:
                    not_defined.append(d)
                
            # Reason #2
            if len(not_defined)>0:
                print(f"RUH-ROH, we have at least one undefined type => {not_defined} for '{i}'");
                missing_type_defs.extend(not_defined)
                missing_type_defs.append(i)
            if any(fdecls) or any(enumdecls):
                if i in collective_types:
                    # Reason #3a - function pointers
                    dprint(f"REASON 3a: '{i}' is COLLECTIVE TYPE")
                    mtch=re.match(r"^\s*(typedef)\s+((struct|union)(\s+__attribute__\(\(.*\)\))?)\s+(\S+)\s*(\{\s*(.*)\s*\}\s*)(\S+)\s*;\s*$",line)
                    if not mtch:
                        dprint(f"ERROR: Expecting '{i}' to be a collective_type [definition:'{line}']")
                    prefix=[mtch.group(1)," ",mtch.group(2)," ",mtch.group(5)," ","{"," "]
                    postfix=[";"," ","}"," ",mtch.group(8),";"]
                    fields=mtch.group(7).strip()
                    fields=fields[:-1] if fields.endswith(';') else fields
                    reqs_=set()
                    x_fields=fields.split(';')
                    for idx,xf in enumerate(x_fields):
                        _ret=self.update_params_for_typeclass(xf,forward_decls,enum_decls)
                        changeit,newparams,fn_noparams,used_fwddecls,used_enumdecls=_ret
                        if changeit:
                            line=f"{fn_noparams}({newparams});"
                            x_fields[idx]=line
                        else:
                            xt=get_basetype_info(xf)
                            if xt in enum_types:
                                print(f"Found 'enum' type: {xt}")
                                if x_fields[idx].startswith('const '):
                                    x_fields[idx]=f"const enum {x_fields[idx][len('const '):]}"
                                else:
                                    x_fields[idx]=f"enum {x_fields[idx]}"
                            elif xt in fwd_decl_types:
                                if type_to_dependencies.get(xt,None) is not None:
                                    ttype=type_to_dependencies[xt]['storage'] 
                                    tname=type_to_dependencies[xt]['defname']
                                    if x_fields[idx].startswith('const '):
                                        x_fields[idx]=f"const {ttype} {x_fields[idx][len('const '):]}"
                                    else:
                                        x_fields[idx]=f"{ttype} {x_fields[idx]}"
                                else:
                                    pass

                    new_fields=";".join(x_fields)
                    line="".join(prefix)+new_fields+"".join(postfix)
                    type_to_dependencies[i]['line']=line
                elif i in fnptr_types:
                    dprint(f"REASON 3b: '{i}' is FNPTR TYPE")
                    # Reason #3b - function pointers 
                    mtch=re.match(r"^\s*(typedef)\s+((\w+(\s+\w+)*)\s+(\(\s*\*\s*(\w+)\))\s*(\((.*)\)))\s*;\s*$",line);
                    _ret=self.update_params_for_typeclass(mtch.group(2),forward_decls,enum_decls)
                    changeit,newparams,fn_noparams,used_fwddecls,used_enumdecls=_ret
                    if changeit:
                        line=f"{mtch.group(1)} {fn_noparams}({newparams});"
                        type_to_dependencies[i]['line']=line
                elif i in simple_types:
                    # Reason #4 
                    bt=type_to_dependencies[i]['base_type']
                    dprint(f"REASON 4: '{i}' is SIMPLE => \"{line}\" (Base type: '{bt}')")
                    line=type_to_dependencies[i]['line']
                    if i in list(fwd_decl_types) and forward_decls.get(i,None) is None:
                        dprint(f"INVESTIGATE THIS: {i} in fwd_decl_types, but not in forward_decls.keys()")
                    # 'struct' or 'union'
                    if forward_decls.get(bt,None) is not None:
                        ref_line=forward_decls[bt]['line'].strip()
                        for prefix in ['struct ','union ']:
                            if ( 
                            (ref_line.startswith(prefix)) and
                            (not line.startswith("typedef "+prefix))
                            ):
                                line=re.sub(r"\btypedef\b",f"typedef {prefix}",line.strip())
                       
                    elif bt in enum_types and not line.strip().startswith("typedef enum"):
                        dprint(f"UPDATING {i} DUE TO ENUM TYPE => {line}");
                        line=re.sub(r"\btypedef\b",f"typedef enum",line.strip())
                       
                    type_to_dependencies[i]['line']=line
                    
                    pass
                    
                else:
                    print(f"ERROR: seems like I should be processing this type: '{i}'.")
                    print(f"=> Line in question: '{line}'")

        problems=set(missing_type_defs)
        plist=copy.copy(problems)
        uses_x=dict()
        KNOWN_TYPES=set(SYSTEM_TYPES+list(DEFINED)+list(enum_types))
        RESOLVED=copy.copy(KNOWN_TYPES)
        
        # Prework - Stage 1 : Identify any type that uses type x for all identified types
        for i,v in type_to_dependencies.items():
            reqs=v['reqs']-set(RESOLVED) # let's get rid of any RESOLVED types being used from the required types
            if uses_x.get(i,None) is None:
                uses_x[i]=set()
            for r in reqs:
                if uses_x.get(r,None) is None:
                    uses_x[r]=set()
                uses_x[r].add(i)
        
        # Prework - Stage 2 : Identify and remove incompleted defined types
        #  gather all the types that are problematic and that use problematic types
        #  and delete them to prevent them from being used
        problematic_types=dict()
        for p in plist:
            if p!="":
                in_use = uses_x.get(p,None)
                if in_use and len(in_use)>0:
                    problems = problems | self.add_to_set(problems,in_use,uses_x)
        if len(problems)>0:
            print(f"WARNING!!! {len(plist)} Types missing their definitions\nWARNING!!! These types missing full definitions are:\nWARNING!!! MISSING: {plist}\n")
            print(f"WARNING!!! These {len(plist)} MISSING TYPES were used by {len(list(problems-plist))} other types")
            print(f"WARNING!!! ALL PROBLEMS => {len(problems)}\nNOTE: PROBLEM SYMS => {problems}")          
            print(f"NOTE: Removing all problem types from consideration. These can be manually addressed if needed.")
            for k in problems:
                if type_to_dependencies.get(k,None) is not None:
                    problematic_types[k]=f"// {k} | {type_to_dependencies[k]['line']}"
                    del type_to_dependencies[k]
                else:
                    problematic_types[k]=f"// {k} | missing definition"
                if uses_x.get(k,None) is not None:
                    del uses_x[k]
        
        
        
        # Prework - Stage 3 : Populate the new requirements without problematic types
        # let's populate the data structures we'll be using to resolve dependencies
        
        x_requires=dict()
        for i,v in type_to_dependencies.items():
            reqs=(v['reqs']-set(RESOLVED)) # let's get rid of any SYSTEM_TYPES being used from the required types 
            lingering_p=[p in reqs for p in problems]
            if any(lingering_p):
                print(f"ERROR: We should not have any problematic (missing definitions) types remaining!")
                bad=list()
                for i in range(0,len(lingering_p)):
                    if lingering_p[i]:
                        bad.append(problems[i])
                print(f"THESE PROBLEMS STILL EXIST => {bad}")
            assert(x_requires.get(i,None) is None)
            x_requires[i]=reqs
        
        orig_x_requires={'original':copy.deepcopy(x_requires)}


            


        # Prework - obtain loose order based on appearance order and basic requirement info
        all_user_defined_types=list()
        for x in appearance_order+list(x_requires.keys())+list(uses_x.keys()):
            if ( (x not in problems) and (x not in ["...",""]) and
                 (x not in RESOLVED) and (x not in all_user_defined_types)
                ):
                all_user_defined_types.append(x)
        definition_order=list()
        undefined=set(all_user_defined_types)

        # Prework - Stage 2 : RESOLVE SIMPLE TYPES FIRST
        for u in all_user_defined_types:
            if u in simple_types:
                u_base=type_to_dependencies[u].get('base_type',None)
                """
                if type_to_dependencies[u].get('deftype',None) is None:
                    u_base=type_to_dependencies[u].get('deftype')
                    line=type_to_dependencies[u].get('line',None)
                else:
                    u_base=type_to_dependencies[u]['deftype']
                """
                
                if u_base is None:
                    pass
                else:
                    if u_base in RESOLVED:
                    # 0) if it's a RESOLVED type, just declare it
                        # remove dependencies on this type
                        for x in uses_x[u]:
                            x_requires_x=x_requires.get(x,None)
                            if x_requires_x and u in x_requires_x:
                                x_requires[x].remove(u)
                        if u not in definition_order:
                            definition_order.append(u)
                        if u in undefined:
                            undefined.remove(u)
                        RESOLVED.add(u)
                        del uses_x[u]
                        continue
                    
                    
                    # or if the u_base does not have any requirements, declare the u_base
                    if x_requires.get(u_base,set())==set() and u_base not in definition_order:
                        if u_base not in definition_order:
                            definition_order.append(u_base)    
                        undefined.remove(u_base)
                        RESOLVED.add(u_base)
                        del uses_x[u_base]

                    # 1) if it's not forward declared, let's fwd declare it unless it's a struct or union
                    elif u_base not in fwd_decl_types:
                        storage=type_to_dependencies[u].get('storage',None)
                        if storage is not None:
                            forward_decls[u_base]={'line':f"{storage} {u_base};",'storage':storage}
                            fwd_decl_types.add(u_base)
                    
                            

                    # 2) replace all u's with u_base
                    uses_x_u=uses_x.get(u,set())  # uses_x[u]
                    uses_x_ubase=uses_x.get(u_base,set()) # uses_x[u_base]
                    x_requires_u=x_requires.get(u,set())  # x_requires[u]
                    x_requires_ubase=x_requires.get(u_base,set()) # x_requires[u_base]
                    if x_requires_ubase is None:
                        x_requires_ubase=set() # make sure that we don't have a None
                    uses_x[u_base] = (uses_x_ubase | uses_x_u)
                    if u in uses_x[u_base]:
                        uses_x[u_base].remove(u)

                    x_requires[u_base] = (x_requires_ubase | x_requires_u)
                    if u in x_requires[u_base]:
                        x_requires[u_base].remove(u)

                    for x in uses_x[u]:
                        x_requires_x=x_requires.get(x,set())
                        x_requires_x.add(u_base)
                        if u in x_requires_x:
                            x_requires_x.remove(u)
                        x_requires[x] = x_requires_x

                    # 3) define u and then remove the uses_x[u] entry
                    if u not in definition_order:
                        definition_order.append(u)
                    undefined.remove(u)
                    RESOLVED.add(u)
                    del uses_x[u]

        orig_x_requires['reduced']=copy.deepcopy(orig_x_requires['original'])
        
        for u in all_user_defined_types:
            if u in simple_types:
                u_base=type_to_dependencies[u].get('base_type',None)
                if u_base in fwd_decl_types and u_base not in KNOWN_TYPES:
                    if ( u_base in orig_x_requires['reduced'][u] and 
                        u in orig_x_requires['reduced'][u_base] ) :
                        orig_x_requires['reduced'][u_base].remove(u)
                        orig_x_requires['reduced'][u_base].add(u_base)



        
        problems=missing_type_defs+list(problems-set(plist)) # let's make sure the original missing types are ordered first
        prev_undefined=None
        while(len(undefined)>0):    
            prev_undefined=copy.copy(undefined)
            updated=False
            for x in undefined:
                dprint(f"DEBUG: Looking at {x}")
                resolvable,checkfwddecl=self.process_rules_for_x(x,x_requires,uses_x,RESOLVED,orig_x_requires,fnptr_types)
                dprint(f"DEBUG: Looked at {x} => Resolvable {resolvable}")
                if resolvable is not None and len(resolvable)>0:
                    updated=True
                    if checkfwddecl is not None and len(checkfwddecl)>0:
                        for f in checkfwddecl:
                            assert f in fwd_decl_types or f in fnptr_types
                    
                    for r in resolvable:
                        dprint(f"DEBUG: RESOLVING {r}")
                        if r not in definition_order:
                            dprint(f"DEBUG: RESOLVED {r}")
                            definition_order.append(r)
                        RESOLVED.add(r)
                        if uses_x.get(r,None) is not None:
                            for n in uses_x[r]:
                                if x_requires.get(n,None) is not None:
                                    if r in x_requires[n]:
                                        x_requires[n].remove(r)
            undefined=undefined-set(RESOLVED)
            if not updated:
                print(f"ERROR! We should be resolving at least one type per iteration")
                print(f"NOTE: These are the remaining unresolved types: {undefined}")
                print(f"NOTE: Exiting to debug")
                for u in undefined:
                    u_info=(u in fwd_decl_types,u in simple_types,u in collective_types,u in RESOLVED)
                    x_requires_u=x_requires.get(u,set())
                    dprint(f"{u}:{x_requires_u}")   
                assert updated

        print("DONE -- with dependencies",flush=True)

        
        typedefs=["\n// POUND DEFINES "]+[pound_defines[x] for x in pnddef]+\
            ["\n// FORWARD DECLS "]+[forward_decls[x]['line'] for x in list(fwd_decl_types)]+\
            ["\n// ENUMERATED TYPES "]+[enum_decls[x] for x in enum_types]+\
            ["\n// THESE TYPES ARE MISSING INFO FOR PROPER RESOLUTION "]+[f"{problematic_types.get(x,'// '+x)}" for x in problems]+\
            ["\n// TYPE RESOLUTION ORDER HERE"]
        recovered_types=simple_types+collective_types+fnptr_types
        
        needs_stdio=False
        if any([i in recovered_types for i in TYPES_REQUIRING_STDIO]):
            needs_stdio=True

        #fh=open('MYORDER','w')
        for e,i in enumerate(definition_order):
            #print(f"{i}",file=fh)      
            line=type_to_dependencies[i]['line']
            if needs_stdio and i in STD_HEADER_TYPES:
                line=f"// included with std headers {i} | "+line
            elif "(...)" in line:
                #transformed_line=re.sub(r'\b\((\*\w+)\)\s*\(\.\.\.\)',r'\1',line);
                transformed_line=re.sub(r'\((\*\w+)\)\s*\(\.\.\.\)',r'\1',line);
                line=f"// included with std headers {i} | "+line
            typedefs.append(line)
        return "\n".join(typedefs),recovered_types,needs_stdio
        



    def rule_one(self,x:str,x_requires:dict,resolved:set):
        valid=None
        lx_requires_x=list(x_requires[x]-resolved)
        dprint(f"DEBUG: x_requires[{x}] = {lx_requires_x}")
        if len(lx_requires_x)==0 or (len(lx_requires_x)==1 and lx_requires_x[0]==x):
            valid=set([x])
            print(f"DEBUG: RULE 1: {x} is valid => {lx_requires_x}")
        return valid
    
    def rule_two(self,x,x_requires:dict,uses_x:dict,resolved:set,fnptr_types:list):
        x_reqs=x_requires[x]-resolved
        uses_x_x=uses_x.get(x,set())-resolved
        req_union=set([ x for y in x_reqs for x in x_requires[y]-resolved ])|x_reqs
        uses_union=set([ x for y in x_reqs for x in uses_x.get(y,[])-resolved ])|uses_x_x
        valid_=None
        print(f"DEBUG: CHECKING RULE 2: {x} is valid [{req_union <= uses_union}] => {req_union} ({uses_union})")
        if req_union <= uses_union:
            valid_=req_union
            if x in fnptr_types:
                valid_.add(x)
            print(f"DEBUG: RULE 2: {x} is valid [{valid_}] => {req_union} ({uses_union})")
        return valid_

    def process_rules_for_x(self,x:str,x_requires:dict,uses_x:dict,resolved:set,orig_x_requires:dict,fnptr_types:list):
        new_defines=None
        check_for_fwddecl=None
        r1=self.rule_one(x,x_requires,resolved)
        if r1:
            new_defines = r1
        else:
            r2=self.rule_two(x,x_requires,uses_x,resolved,fnptr_types)
            if r2:
                new_defines=self.reorder_(r2,x_requires,orig_x_requires,fnptr_types)
                #new_defines = r2
                check_for_fwddecl = r2
        return new_defines,check_for_fwddecl

    def reorder_(self,resolvable,x_requires,orig_x_requires,fnptr_types):
        
        first=list()
        second=list()
        third=list()
        fourth=list()
        initial_x_requires=orig_x_requires['original']
        reduced_x_requires=orig_x_requires['reduced']
        dprint(f"DEBUG: RESOLVABLE => {resolvable}")
        for idx,o in enumerate(resolvable):
            dprint(f"DEBUG: {o} [resolvable:{resolvable}] | {reduced_x_requires[o]} || {initial_x_requires[o]}")
            not_o=copy.copy(resolvable).remove(o)
            # intersect the original x_requires[o] with current resolvable set
            # if this is empty, add it because we have no direct uses and any typedef'd struct is fwd declared
            direct_unresolved = list(resolvable & reduced_x_requires[o])
            dprint(f"DEBUG: CHECK(0) for {o}: direct_unresolved=> {direct_unresolved} [reduced_x_requires: {reduced_x_requires[o]}]")
            if o in reduced_x_requires[o]:
                if o in direct_unresolved and o in initial_x_requires[o]:
                    if len(direct_unresolved)>1:
                        # let's put self-referencing type declarations that depend on other unresolved types at the end
                        dprint(f"DEBUG: FOURTH(1): {o} [{x_requires[o]}] => {direct_unresolved} [{initial_x_requires[o]}]")
                    fourth.append(o)
                    else:
                        dprint(f"DEBUG: FOURTH(2): {o} [{x_requires[o]}] => {direct_unresolved} [{initial_x_requires[o]}]")
                        fourth.insert(0,o)
                
                else:
                    first.append(o)    
                    dprint(f"DEBUG: FIRST: {o} [{x_requires[o]}] => {direct_unresolved} [{initial_x_requires[o]}]")

            elif len(direct_unresolved)==0:
                dprint(f"DEBUG: SECOND: {o} [{x_requires[o]}] => {direct_unresolved} [{initial_x_requires[o]}]")
                second.append(o)
            else:
                dprint(f"DEBUG: THIRD: {o} [{x_requires[o]}]= > {direct_unresolved} [{initial_x_requires[o]}]")
                third.append(o)
        # else the remaining order doesn't matter
                
        resolved_order= first+second+third+fourth
        dprint(f"DEBUG: RESOLVED ORDER {resolved_order}")
        return resolved_order


        
                    



    


            

            





    # given typedef mapping, create defs
    def cleanup_typedefs(self, structDump):
        definitions = ""
        structDump = self.typedef_firstpass(structDump)
        structDump = self.typedef_secondpass(structDump)
        structDump = self.typedef_lastpass(structDump)
        structDump = self.rearrange_typedefs(structDump)
        return structDump

    def get_funcBody(self, lines, funcHeaders):
        inFunc = False
        funcBody = ""
        funcList = []

        for line in lines.splitlines():
            if not inFunc:
                for header in funcHeaders:
                    if header.strip(";") == line.strip():
                        inFunc = True
            elif IDA_SECTION_END in line:
                    inFunc = False
                    funcList.append(funcBody)
                    funcBody = ""
            else:
                funcBody += line + "\n"

        return funcList

    def get_consts(self, lines):
        consts = {}
        constMap = {}
        assignMap = {}

        for line in lines.splitlines():
            line = line.strip()
            if line.startswith("const"):
                #print("Found const variable: ", line)
                header = line.strip().split(";")[0]
                name = header.rsplit(maxsplit=1)[1].strip()
                consts[line] = name
            elif "=" in line:
                for init, name in consts.items():
                    if line.startswith(name):
                        array = line.split("=")
                        value = array[1].strip().strip(";")
                        constMap[init] = value
                        assignMap[init] = line
                        break

        return constMap, assignMap

    def handle_const_assigns(self, lines, funcHeaders):

        funcs = self.get_funcBody(lines, funcHeaders)
        # print(funcs)
        for f in funcs:
            constMap, assignLineMap = self.get_consts(f)
            newFunc = f
            for line, value in constMap.items():
                assignLine = assignLineMap[line]
                #print("removing assignment", assignLine)
                newFunc = newFunc.replace(assignLine, "")

                array = line.strip().split(";")
                header = array[0]
                comments = array[1]
                newHeader = header.strip().strip(";") + " = " + value + "; " + comments + "\n"
                newFunc = newFunc.replace(line, newHeader)

            lines = lines.replace(f, newFunc)


        return lines


    def remove_nonCGC_calls(self, output, targets):
        for target in targets:
            matches = re.findall("\\\n[\w\s*]*"+target+"\\(", output)
            for m in matches:
                newLine = m.replace(target, "// "+target)
                output = output.replace(m, newLine)
        return output

    # remove decompilation artifacts
    # basic string replacement to standardize the typedef replacements
    def remove_artifacts(self, lines, use_new_features):
        newlines = ""
        for line in lines.splitlines():
            if "<defs.h>" in line:
                continue
            elif line.startswith("#define "):
                newlines += line+"\n"
                continue
            # print(line)
            
            # print("---------")
            if "__cdecl" in line:
                # print("replacing line")
                line = line.replace("__cdecl", "")
                # print("newline", line)

            ## handle :: classes (let's translate after everything is generated)
            #line = line.replace("::", "__")

            # replace namings
            if not use_new_features:
                line = line.replace("int64", "long")
                line = line.replace("int32", "int")
                line = line.replace("int16", "short")
                line = line.replace("int8", "char")

                line = line.replace("bool", "_Bool")
                line = line.replace("_Bool", "_BoolDef") # TODO: dont use this dumbass workaround
                line = line.replace("_BoolDef", "bool")

                line = line.replace("_DWORD", "int")
                line = line.replace("_WORD", "short")
                line = line.replace("_BYTE", "char")
                line = line.replace("_UNKNOWN", "void")


                # strip __ precursors
                line = line.replace(" __long", " long")
                line = line.replace(" __int", " int")
                line = line.replace(" __short", " short")
                line = line.replace(" __char", " char")
            else:
                line = re.sub(r"\bint64\b", "long",line)
                line = re.sub(r"\bint32\b", "int",line)
                line = re.sub(r"\bint16\b", "short",line)
                line = re.sub(r"\bint8\b", "char",line)

                line = re.sub(r"\bbool\b", "_Bool",line)
                line = re.sub(r"\b_Bool\b", "_BoolDef",line) # TODO: dont use this dumbass workaround
                line = re.sub(r"\b_BoolDef\b", "bool",line)

                line = re.sub(r"\b_DWORD\b", "int",line)
                line = re.sub(r"\b_WORD\b", "short",line)
                line = re.sub(r"\b_BYTE\b", "char",line)
                line = re.sub(r"\b_UNKNOWN\b", "void",line)


                # strip __ precursors
                line = re.sub(r"\b__long\b", "long",line)
                line = re.sub(r"\b__int\b", "int",line)
                line = re.sub(r"\b__short\b", "short",line)
                line = re.sub(r"\b__char\b", "char",line)



            # line = line.replace("LOWORD", "")

            newlines += line+"\n"
        return newlines

    def get_data_declarations(self, lines, data_syms,gdataMap:dict, global_dataLines_:list):
        inData = False
        #dataLines_ = []
        dataLines = []
        ldataMap_ = {}
        removeList = []
        capture=False
        for line in lines.splitlines():
            if IDA_DATA_START in line:
                inData = True
                if len(global_dataLines_)<=0:
                    global_dataLines_.append("\n//"+"-"*68)
                    global_dataLines_.append(line+"\n")
                continue
            elif IDA_SECTION_END in line:
                inData = False
                continue

            if inData and len(line.strip()) > 0:
                dataLines.append(line)
                if line not in global_dataLines_ and not capture and (";" in line or '=' in line):
                    capture=True

            if capture:
                global_dataLines_.append(line)
                if ";" in line:
                    capture=False

        print("GLOBAL DATA LINES : \n["+"\n".join(global_dataLines_)+"\n]\n")
        gdataMap, ldataMap_ = self.process_datalines(dataLines,data_syms,gdataMap)

        return gdataMap, removeList, ldataMap_, global_dataLines_

    def process_datalines(self, dataLines, data_syms, gdataMap:dict):
        line = ""
        new_syms, ext_syms = (set(),set())
        ldataMap_ = {'prototypes':dict(),'sym2proto':dict(),'ext_vars':set(),'local_vars':set()} 
        print("[RUNNING] process_datalines",flush=True)
        for dataLine in dataLines:
            print(dataLine)
            if "Elf" in dataLine:
                # removeList.append(dataLine+"\n")
                continue
            line += dataLine
            if ";" not in dataLine:
                line += "\n"
                continue
            line = line.strip().split(";")[0] + ";"
            #print("Original:", line)
            header = line.split("=")[0].strip()

            if header.startswith("//"):
                header = header[3:] # handle commented out cases

            dataType, dataName = self.getTypeAndLabel(header.split('=',1)[0])
            base_dataName=dataName.split('[',1)[0]

            if base_dataName not in data_syms:
                new_syms.add(base_dataName)
                print("{} [NOT A DATA SYMBOL]".format(base_dataName))
                line = ""
                continue
            else:
                print("{} [DATA SYMBOL]".format(base_dataName))
                ext_syms.add(base_dataName)
                
            array_size=len(re.findall("\[\d*\]",dataName))
            print("Array Size:", array_size)
            defLine=""
            if array_size>=2:
                print("// --- WARNING! Two-dimensional array objects are not yet supported")
                defLine += "%s *(p%s);\n" %(dataType, dataName)
                dataName = dataName.split("[")[0] # handle arrays
                defLine += "#define %s (*p%s)\n" % (dataName, dataName)
                print(" // --- END OF WARNING!\n")
            elif array_size==1 and (("*" not in dataType) or ("*" in dataType and "[]" in dataName)):
                dataName = dataName.split("[")[0] # handle arrays
                defLine = "%s *(p%s);\n" %(dataType, dataName)
                defLine += "#define %s (p%s)\n" % (dataName, dataName)
            else:
                defLine = "%s *(p%s);\n" %(dataType, dataName)
                dataName = dataName.split("[")[0] # handle arrays
                defLine += "#define %s (*p%s)\n" % (dataName, dataName)

            if line.startswith("//"):
                defLine += "//"
            print("    ---->", defLine)
            x=gdataMap.get(line,None)
            if not x:
                print("    New global variable : ", defLine)
                gdataMap[line] = defLine
            ldataMap_['prototypes'][line] = defLine
            ldataMap_['sym2proto'][base_dataName] = line
            line = ""

        #      gdataMap [global] ; ldataMap_ [per fn]
        ldataMap_['ext_vars']=ext_syms
        ldataMap_['local_vars']=new_syms
        print("[COMPLETED] process_datalines",flush=True)
        return gdataMap, ldataMap_


    def split_func_args(self, argString):
        args = []
        currentArg = ""
        inBracket = False
        for c in argString:
            if c == "," and not inBracket:
                args.append(currentArg)
                currentArg = ""
            else:
                if c == "(":
                    inBracket = True
                elif c == ")":
                    inBracket = False

                currentArg += c

        if currentArg: #add last elem
            args.append(currentArg)

        return args

    def add_to_set(self,x,y,lut):
        diff = y-x
        x=x | diff
        for d in list(diff):
            if lut.get(d,None) is not None:
                x= x | self.add_to_set(x,lut[d],lut)
        return x

    def resolve_dependencies(self,stubs_per_func,dataMap_per_func):
        unresolved=set(sorted(stubs_per_func.keys()))
        nm_to_decomp=dict()
        global_proto_var=dict()
        
        #symvar_to_proto=dict()
        fn_list=stubs_per_func.keys()
        #dataMap_per_func[fn] = {'prototypes':dict(),'sym2proto':dict(),'ext_vars':set(),'local_vars':set()} 
        # get unique set of ext_vars that need to be added to list, then post-process to get lines from 'sym2proto' LUT

        #print(f"fn_list : {fn_list}")
        for i in fn_list:
            j=stubs_per_func[i]
            if not isinstance(j,dict):
                print(f"Warning: Function {i} does not have symbols or names from nm")
            else:
                nms=j['nm_names']
                syms=j['symbols']
                for k in range(0,len(syms)):
                    x=nm_to_decomp.get(nms[k],None)
                    if not x:
                        nm_to_decomp[nms[k]]=set([syms[k]])
                    else:
                        nm_to_decomp[nms[k]].add(syms[k])
                j=dataMap_per_func[i]
                prot=j['prototypes']
                for k in prot.keys():
                    x=global_proto_var.get(k,None)
                    if not x:
                        global_proto_var[k]=prot[k]
                #syms=j['sym2proto']
                #for k in syms.keys():
                #    x=symvar_to_proto.get(k,None)
                #    if not x:
                #        symvar_to_proto[k]=set([syms[k]])
                #    else:
                #        symvar_to_proto[k].add(syms[k])
                    
        resolved=set()
        ext_varprotos=dict()
        ext_vars=dict()
        ext_protos=dict()
        ext_dsyms=dict()
        ext_syms=dict()
        local_syms=dict()
        resolved_local_syms=dict()
        resolved_fn=dict()
        for f in sorted(unresolved):
            stub=stubs_per_func[f]
            dm=dataMap_per_func[f]
            ext_varprotos[f]=set(dm['prototypes'])
            ext_vars[f]=set(dm['ext_vars'])
            ext_protos[f]=set([stub['prototypes'][i] for i in range(0,len(stub['prototypes'])) if stub['external'][i] ])
            ext_dsyms[f]=set([stub['symbols'][i] for i in range(0,len(stub['prototypes'])) if stub['external'][i] ])
            ext_syms[f]=set([stub['nm_names'][i] for i in range(0,len(stub['prototypes'])) if stub['external'][i] ])
            local_syms[f]=set([stub['nm_names'][i] for i in range(0,len(stub['prototypes'])) if not stub['external'][i] ])
            resolved_local_syms[f]=set()
            print(f"{f}: 'ext_varprotos:{sorted(ext_varprotos[f])}'")
            print(f"{f}: 'ext_vars:{sorted(ext_vars[f])}'")
            print(f"{f}: 'ext_protos:{sorted(ext_protos[f])}'")
            print(f"{f}: 'ext_syms:{sorted(ext_syms[f])}'")
            print(f"{f}: 'ext_dsyms:{sorted(ext_dsyms[f])}'")
            print(f"{f}: 'local_syms:{sorted(local_syms[f])}'")
            resolved_fn[f]=set()
        print(f"UNRESOLVED = {unresolved}")
        #fn=random.choice(list(unresolved)) if "main" not in unresolved else "main"
        rslv=sorted(unresolved)
        for fn in rslv:
            x=set([fn])
            locs=set(sorted(local_syms[fn]))
            resolved_local_syms[fn]=self.add_to_set(x,locs,local_syms)
        for fn in rslv:
            for l in sorted(resolved_local_syms[fn]):
                try:
                    ext_varprotos[fn] = ext_varprotos[fn] | ext_varprotos[l]
                    ext_vars[fn] = ext_vars[fn] | ext_vars[l]
                    ext_protos[fn] = ext_protos[fn] | ext_protos[l]
                    ext_dsyms[fn] = ext_dsyms[fn] | ext_dsyms[l]
                    ext_syms[fn] = ext_syms[fn] | ext_syms[l]
                except Exception as e:
                    print(f"fn={fn}, l={l}")
                    print(e)
                    raise(e)
            unresolved.remove(fn)
            resolved.add(fn)
            print(f"[DONE] -- {f} -- resolved external symbol dependencies")
        for rf in sorted(resolved):
            print("RESOLVED:")
            print(f"{rf}: 'ext_varprotos:{sorted(ext_varprotos[rf])}'")
            print(f"{rf}: 'ext_vars:{sorted(ext_vars[rf])}'")
            print(f"{rf}: 'ext_protos:{sorted(ext_protos[rf])}'")
            print(f"{rf}: 'ext_syms:{sorted(ext_syms[rf])}'")
            print(f"{rf}: 'ext_dsyms:{sorted(ext_dsyms[rf])}'")
            print(f"{rf}: 'resolved_local_syms:{sorted(resolved_local_syms[rf])}'")
            
            
        print("Resolved dependencies on external symbols:")
        resolved_fn_syms=dict()
        resolved_var_syms=dict()
        for f in fn_list:
            p=sorted(ext_protos[f])
            s=sorted(ext_dsyms[f])
            n=sorted(ext_syms[f])
            
            resolved_fn_syms[f]={'prototypes':list(p),
                                  'symbols':list(s),
                                  'nm_names':list(n),
                                  }
            v=sorted(ext_varprotos[f])
            #for k in v:
            #    for s in symvar_to_proto[k]:
            #        p.add(s)
            #        global_proto_var[k]=prot[k]
            
            resolved_var_syms[f] = {k:global_proto_var[k] for k in v }

        return resolved_fn_syms, resolved_var_syms, nm_to_decomp

    def get_guessed_funcs(self,lines):
        lines_=[ l for l in lines.splitlines() if l.startswith('//') and "guessed type" in l]
        guesses=list()
        for x in lines_:
            res=re.match(r"// [0-9A-F]+: using guessed type ((.*)(\(.*\));)",x)
            if res:
                typ,lbl=self.getTypeAndLabel(res.group(2))
                guesses.append((typ,lbl,res.group(1)))

        return guesses




    def get_stubs(self, lines, stubs, funcs, decomp_re, global_decomp, 
        fn_symbols, glibc_symbols, data_symbols, translate_dict,
        guessed_protos, prev_global):
        # stubs, funcHeaders, h, s, f, d, g = cleaner.get_stubs(decomp_code,stubs,funcHeaders,detours_re,decomp_decls)
        instubs = False
        isFunc = False
        lstubs = {'prototypes':list(),'symbols':list(),'external':list(),'nm_names':list(),'is_glibc':list()}
        lfuncs = {'prototypes':list(),'symbols':list(),'external':list(),'nm_names':list(),'is_glibc':list()}
        global_fns = []
        guessed_fn=[x[1] for x in guessed_protos]
        guessed_pr=[x[2] for x in guessed_protos]
        weaker_conflicts = []
        
        lines_=lines.splitlines()
        fn_start=-1
        fulldecomp=lines_
        print("[RUNNING] get_stubs",flush=True)
        for idx,line in enumerate(lines_):
            if IDA_STUB_START in line:
                isFunc = False
                instubs = True
                print("[get_stubs] [{}][{}] {}".format(instubs,isFunc,line),flush=True)
                continue
            elif IDA_SECTION_END in line:
                if IDA_DECOMP_START in line and fn_start==-1:
                    fn_start=idx
                instubs = False
                isFunc = True
                print("[get_stubs] [{}][{}] {}".format(instubs,isFunc,line),flush=True)
                continue
            
            line = line.strip()
            print("[get_stubs] line : {}".format(line),flush=True)
            if instubs and len(line.strip()) > 0:
                # if the stub isn't a decompiled function
                # this looks like the right solution, but has problematic corner cases
                #decomp=decomp_re.search(line.split('(',1)[0].rsplit('\s',1)[-1])
                preparse_line=line.rsplit('=',1)[0].rsplit('(',1)[0]
                print("[get_stubs] preparse_line: {}".format(preparse_line),flush=True)
                while preparse_line.count('(') != preparse_line.count(')'):
                    x=preparse_line.rsplit('(',1)[0]
                    print("[get_stubs] preparse_line: {} => {}".format(preparse_line,x),flush=True)
                    preparse_line=x
                    
                print("[get_stubs] [done] preparse_line: {}".format(preparse_line),flush=True)
                sym_type, sym_name=self.getTypeAndLabel(preparse_line)
                #print(f"[get_stubs] [done] type : {sym_type}, label : {sym_name}",flush=True)
                nm_sym_name=sym_name
                found_glibc=False
                if sym_name in data_symbols:
                    print("Found a data symbol! '{}'".format(sym_name))
                    
                elif sym_name in glibc_symbols:
                    print("Found a glibc symbol! '{}'".format(sym_name))
                    found_glibc=True
                    # the following doesn't work if the equivalent variable function isn't an available symbol in binary
                    #if sym_name in list(VALIST_TRANSFORM.keys()):
                    #    new_sym=VALIST_TRANSFORM[sym_name]
                    #    translate_dict[sym_name]=new_sym
                    #    nm_sym_name=new_sym

                    if line.lstrip().startswith("//"):
                        line = line.lstrip()[2:]
                elif sym_name not in fn_symbols:
                    print("Function declaration symbol name '{}' doesn't exist in symbol list!".format(sym_name))
                    print("line => {}".format(line))
                    print("Checking to see if it's an inlined alias, which is usually <fn>_\d+")
                    new_sym=re.sub(r'^(\w+)(_\d+)$',r'\1',sym_name)
                    alt_sym="_"+sym_name
                    print(f"NEW SYM: {new_sym}\tALT SYM: {alt_sym}")
                    # hex-rays either gets rid of prepended _ character or appends _\d+ for inlined functions
                    if  sym_name == "patchmain":
                        translate_dict[sym_name]="main"
                        nm_sym_name="main"
                    elif new_sym != sym_name and new_sym in fn_symbols:
                        #line = re.sub(r'\b'+sym_name+r'\b',new_sym,line)
                        #sym_name=new_sym
                        translate_dict[sym_name]=new_sym
                        nm_sym_name=new_sym
                    elif alt_sym in fn_symbols:
                        print("We're good! Decompiler stripped prepended '_' character")
                        translate_dict[sym_name]=alt_sym
                        translate_dict[alt_sym]=sym_name
                        nm_sym_name=alt_sym
                        
                    else:
                        print("Error: can't resolve symbol '{}'".format(sym_name))
                        print("Skipping line")
                        continue
                decomp=decomp_re.search(sym_name)
                print("decomp_re : "+str(decomp_re)+f" => {decomp}")                    
                        
                lstubs['symbols'].append(sym_name)
                
                lstubs['nm_names'].append(nm_sym_name)
                lstubs['is_glibc'].append(found_glibc)
                skip_prototype=False
                if decomp:
                    print("FOUND DECOMPILED FUNCTION  '{}' : {}".format(decomp.group(0),line))
                    lstubs['external'].append(False)
                    if decomp.group(0) in guessed_fn:
                        indx=guessed_fn.index(decomp.group(0))
                        guess_proto=guessed_pr[indx]
                        xline=line.rsplit(';',1)[0].strip()
                        gproto=guess_proto.rsplit(';',1)[0].strip()
                        print(f"GUESSED PROTOTYPE: {gproto} vs LINE : {xline}")
                        if xline==gproto:
                            print(f"a guessed prototype is in the decompiled function list")
                            print(f"ignoring the guess and using the concrete decompiled function prototype")
                            skip_prototype=True

                else:
                    print("FOUND EXTERNAL FUNCTION  '{}' : {}".format(sym_name,line))
                    lstubs['external'].append(True)

                if skip_prototype:
                    lstubs['prototypes'].append("")
                else:
                    lstubs['prototypes'].append(line)
                    
                if line not in stubs['prototypes'] and not decomp:
                    stubs['symbols'].append(sym_name)
                    stubs['prototypes'].append(line)
                    stubs['external'].append(True)
                    stubs['nm_names'].append(nm_sym_name)
                    stubs['is_glibc'].append(found_glibc)
                elif line not in stubs['prototypes'] and decomp and line not in global_decomp and not skip_prototype:
                    print(f"global function [{sym_name}] => {line}")
                    print(f"global decomp => {global_decomp}")
                    print(f"stubs[prototypes] => {stubs['prototypes']}")
                    dont_push=False
                    for gindex,proto_ in enumerate(prev_global):
                        print(f"DEBUG [{sym_name}]: '{proto_}'")
                        if re.search(r"\b("+sym_name+r")\s*\(\b",proto_):
                            print(f"CONFLICT in Decompiled prototypes for {sym_name} [previous => {proto_}")
                            if proto_.strip().endswith("// idb"):
                                print(f"Need to remove previous declaration: {proto_}")
                                print(f"and use current declaration: {line}")
                                weaker_conflicts.append(proto_)
                            else:
                                print(f"Can't use current declaration: {line}")
                                print(f"Need to use previous declaration: {proto_}")
                                dont_push=True
                    if not dont_push:
                        global_fns.append(line)
                else:
                    continue
            elif isFunc and len(line.strip()) > 0 and not line.startswith("//"): #is part of function declarations
                isFunc = False
                preparse_line=line.rsplit('=',1)[0].rsplit('(',1)[0]
                while preparse_line.count('(') != preparse_line.count(')'):
                    preparse_line=preparse_line.rsplit('(',1)[0]
                sym_type, sym_name=self.getTypeAndLabel(preparse_line)
                nm_sym_name=sym_name
                if sym_name not in fn_symbols:
                     if sym_name=="patchmain":
                        nm_sym_name="main"
                     else:
                         for n in [re.sub(r'^(\w+)(_\d+)$',r'\1',sym_name),"_"+sym_name]:
                             if n in fn_symbols and n!=sym_name:
                                 nm_sym_name=n
                                 break
                lfuncs['prototypes'].append(line)
                lfuncs['symbols'].append(sym_name)
                lfuncs['external'].append(False)
                lfuncs['nm_names'].append(nm_sym_name)
                lfuncs['is_glibc'].append(found_glibc)
                if line not in funcs['prototypes']:
                    funcs['prototypes'].append(line)
                    funcs['symbols'].append(sym_name)
                    funcs['external'].append(False)
                    funcs['nm_names'].append(nm_sym_name)
                    funcs['is_glibc'].append(found_glibc)
                else:
                    continue

        #sections=(lines_[stub_idxs[0]]:stub_idxs[1]], lines_[stub_idxs[1]]:stub_idxs[-1]] )
        #stubs, funcHeaders, header_decls, s, f = cleaner.get_stubs(decomp_code,stubs,funcHeaders,header_decls)
        print("[COMPLETED] get_stubs",flush=True)
                                         # s
        return stubs, funcs, fulldecomp, lstubs, lfuncs, fn_start, global_fns,translate_dict, weaker_conflicts

    def split_decomp(self, lines):
        dataLines = []
        funcstubLines = []
        funcdefLines = []
        inStubs = False
        inFunc = False
        inData = False
        lines_=lines.splitlines()
        for idx,line in enumerate(lines_):
            if IDA_STUB_START in line:
                inStubs = True
                inData = False
                inFunc = False
            elif IDA_DATA_START in line:
                inStubs = False
                inData = True
                inFunc = False
            elif IDA_DECOMP_START in line:
                inStubs = False
                inData = False
                inFunc = True
            elif IDA_SECTION_END in line:
                inStubs = False
                inData = False
                inFunc = False
            
            if inData:
                dataLines.append(line)
            elif inStubs:
                funcstubLines.append(line)
            elif inFunc:
                funcdefLines.append(line)
        return dataLines,funcstubLines,funcdefLines

    def get_stub_name(self, stubLine):
        header = stubLine.split("(", maxsplit=1)[0]
        if header.startswith("//"):
            header = header[3:]
        stubType, name = self.getTypeAndLabel(header)
        return name

    # given list of stubs, create stubs
    def make_pcgc_stubs(self, stublines, funcs, glibc_symbols):
        stubMap = {}
        stdio_collision = []
        
        for stub in stublines['prototypes']:
            skip = False
            for funcline in funcs:
                if funcline in stub:
                    skip = True # skip functions that are already declared below
                    # print(funcline, "in", stub)
                    break
            if skip:
                # print("Skipping ", stub)
                continue

            print("Processing stub ", stub)
            array = stub.split("(", maxsplit=1)
            header = array[0]
            if IDA_WEAK_LABEL in stub:
                self.weakFuncs.append(stub)
                print(f"WEAK FUNCTION: {stub}")
            # handle comments
            args = array[1].split(";", maxsplit=1)[0][:-1] #strip ) and ;

            argsList = self.split_func_args(args) # args.split(",")
            argTypes = []

            # print("arglist", argsList)

            count = 0
            for arg in argsList:
                arg = arg.strip()
                if arg: # skip empty args
                    if arg == "...":
                        argTypes.append("...")
                        continue
                    argTuple = self.getTypeAndLabel(arg)
                    argType = argTuple[0]
                    if len(argTuple) < 2:
                        argName = "arg%d" % count
                        count += 1
                    else:
                        argName = argTuple[1]

                    print("    - ", argType, "||", argName)
                    argTypes.append(argType)


            if header.startswith("//"):
                header = header[3:] # handle commented out cases
            
            ret_type, label = self.getTypeAndLabel(header)
            
            is_glibc=label in glibc_symbols if glibc_symbols else False

            print(f"MAKE_PCGC_STUBS: STUB => '{stub}' [{label} is a GLIBC: {is_glibc}]")
            print("    - RET [%s] LABEL [%s] ARGTYPES[%s] IS_GLIBC[%s]" % (ret_type, label, argTypes, is_glibc))
            valist_start=""
            valist_end=""
            
            if not is_glibc and label not in CSTDIO_FUNCS:
                stubArgs = ", ".join(argTypes)
                stubLine = "typedef " + ret_type + " (*p" + label + ")("+stubArgs+");\n"
                stubNull = "p"+label+" "+label+" = NULL;\n"
                stubMap[stub] = stubLine + stubNull
                
            elif not is_glibc and label in CSTDIO_FUNCS:
                stubArgs = ", ".join(argTypes)
                stubLine = "typedef " + ret_type + " (*p" + label + ")("+stubArgs+");\n"
                stubNull = "p"+label+" "+GLIBC_XFORM_PREFIX+label+" = NULL;\n"
                stubMap[stub] = stubLine + stubNull
                stdio_collision.append((label,GLIBC_XFORM_PREFIX+label))
                
            elif label in list(VALIST_TRANSFORM.keys()):
                returns_value=(ret_type.strip()!="void")                
                stubArgParams=[(s,f"s_{idx}") for idx,s in enumerate(argTypes[:-1])]
                stubArgVals=[s[1] for s in stubArgParams]
                stubArgs=",".join([f"{s[0]} {s[1]}" for s in stubArgParams])+",..."
                
                valist_start=f"    va_list argptr;\n    va_start(argptr,{stubArgParams[-1][-1]});\n"
                valist_end  =f"    va_end(argptr);\n"
                stubParams=",".join(stubArgVals)+",argptr"
                tlabel=VALIST_TRANSFORM[label]
                stubLine = "typedef " + ret_type + " (*p" + label + ")("+stubArgs+");\n"
                stubNull = "p"+label+" "+STUB_PREFIX+label+" = NULL;\n"
                valist_workaround=[
                    f"\n// VA_LIST workaround for variadic glibc symbol: {label}\n",
                    f"{ret_type} {GLIBC_XFORM_PREFIX}{label} ({stubArgs}) "+"{\n",
                    f"    {ret_type} ret;\n" if returns_value else '    \n',
                    valist_start,
                    f"    ret = " if returns_value else "    ",
                    f"{tlabel}({stubParams});\n",
                    valist_end,
                    f"    return ret;\n" if returns_value else "    return;\n",
                    '}\n'
                ]
                stubMap[stub] = stubLine + stubNull + "".join(valist_workaround)
                # ehhhh, we're not going to take away the original function pointer to VA_LIST

            else:
                #stubArgs = ", ".join(argTypes)
                returns_value=(ret_type.strip()!="void")
                stubArgs=""
                stubParams=""
                
                is_void=all(["void"==x.strip() for x in argTypes])
                if not is_void:
                    stubArgParams=[(s,f"s_{idx}") for idx,s in enumerate(argTypes)]
                    stubArgVals=[s[1] for s in stubArgParams]
                    stubArgs=",".join([f"{s[0]} {s[1]}" for s in stubArgParams])
                    stubParams=",".join(stubArgVals)
                
                
                stubLine = "typedef " + ret_type + " (*p" + label + ")("+stubArgs+");\n"

                stubNull = "p"+label+" "+STUB_PREFIX+label+" = NULL;\n"
                glibc_workaround=[
                    f"\n// PLT ebx workaround for glibc symbol: {label}\n",
                    f"{ret_type} {GLIBC_XFORM_PREFIX}{label} ({stubArgs}) "+"{\n",
                    f"    p{label} l{label} = {STUB_PREFIX}{label};\n",
                    f"    {ret_type} ret;\n" if returns_value else '    \n',
                    '    unsigned int localEBX;\n',
                    '    unsigned int localorigPLT_EBX=origPLT_EBX;\n',
                    '    asm (\n',
                    '    \"movl %[LOCALEBX],%%ebx\\n\\t\"\n',
                    '    \"movl %%ebx,%[PLT_EBX]\\n\\t\"\n',
                    '    :[LOCALEBX] \"=r\"(localEBX)\n',
                    '    :[PLT_EBX] \"r\"(localorigPLT_EBX)\n',
                    '    : \"%ebx\"\n',
                    '    );\n',
                    f"    ret = " if returns_value else "    ",
                    f"l{label}({stubParams});\n",
                    '    asm (\n',
                    '    "movl %%ebx,%[LOCALEBX]\\n\\t\"\n',
                    '    :[LOCALEBX]"=r"(localEBX)\n',
                    '    );\n',
                    f"    return ret;\n" if returns_value else "    return;\n",
                    '}\n'
                ]
                stubMap[stub] = stubLine + stubNull + "".join(glibc_workaround)
            

        return stubMap, stdio_collision

    def replace_stubs(self, output, stubMap):
        for stub, replacement in stubMap.items():
            output = output.replace(stub, replacement)
        return output

    def prevent_glibc_collision(self,inlines,glibc_funcs):
        stdio_fns='|'.join([ re.escape(g) for g in glibc_funcs])
        
        #print(f"STDIO_FNS: ({stdio_fns})")
        #GLIBC_XFORM_PREFIX
        stdio_re=re.compile(r'\b'+f"({stdio_fns})"+r'\b')
        
        return [ 
            re.sub(r"(?<!->)\b"+f"(?<!\.)({stdio_fns})"+r"\b",GLIBC_XFORM_PREFIX+r"\1",i)
            for i in inlines
        ]
        #return [stdio_re.sub(r"x__\\1",i) for i in inlines]


    def replace_data_defines_list(self, output, dataMap, removeList):
        for data, replacement in dataMap.items():
            print("   ---> Replacing [[%s]] with [[%s]]" %(data, replacement))
            if '\n' not in data:
                for i in range(0,len(output)):
                    output[i] = output[i].replace(data, replacement)
            else:
                x=data.split('\n')
                for i in range(0,len(output)):
                    if output[i].startswith(x[0]):
                        swap=len(x)
                        output[i]=replacement+"\n /*"+output[i];
                        output[i+swap-1]+="*/";
        for target in removeList:
            for i in range(0,len(output)):
                output[i] = output[i].replace(target, "")
        return output

    def transform_std(self,decomp):
        d=re.sub(r"(\S+)::\$?([_\S]+)",r"\1___\2",decomp)
        d=re.sub(r"(\S+)::\$?([_\S]+)",r"\1___\2",d)
        return d

    def transform_cpp(self,decomp):
        # s/_cppobj //g
        d=re.sub(r"\b_thiscall\b",r"",decomp)
        d=re.sub(r"\b_cppobj\b",r"",d)
        # s/(\w+)<(\w+)>/${1}_${2}_/g
        d=re.sub(r"(\S+)::(\S+)",r"\1___\2",d)
        # s/(\w+)<(\w+)*>/${1}_${2}_p_/g
        d=re.sub(r"(\S+)<(\S+)*>",r"\1_\2_p_",d)
        # s/(\w+)::(\w+)/${1}___${2}/g
        d=re.sub(r"(\S+)<(\S+)>",r"\1_\2_",d)
        # let's get rid of ::$[0-9a-fA-F]

        return d


       
    def replace_data_defines(self, output, dataMap, removeList):
        for data, replacement in dataMap.items():
            print("   ---> Replacing [[%s]] with [[%s]]" %(data, replacement))
            output = output.replace(data, replacement)
        for target in removeList:
            output = output.replace(target, "")
        return output


    def rename_target(self, output, target):
        if target == "main": # special case
            output = output.replace(target, "mypatch"+target)
        else:
            output = output.replace(target, "my"+target)
        return output

    def generate_det_placeholders(self):
        placeholders = "\nvoid __prd_init() {\n}\n"
        placeholders += "void __prd_exit() {\n}\n"
        return placeholders


    def generate_wrapper(self, target_list, funcs, stubMap, dataMap, detour_prefix, translation_dict,demang2mangLUT,glibc_symbols):
        rev_trans={v:k for k,v in translation_dict.items()}
        mainStub = "int main()\n" + \
               "{\n"
        mainStub_t="";
        mainStub_pre=list();
        mainStub_post=list();
        wrapperStub = ""
        #translation_dict = dict()
        # keys are the expected decompiled function name, value is actual decompiled function name
        call_me=dict()
        for target in target_list:
            #trans_targ=rev_trans.get(target,target) if target != "main" else "main"
            trans_targ=translation_dict.get(target,target)
            ltarget=target
            if trans_targ=="main":
                ltarget="patchmain"
            detour_target="{}{}".format(detour_prefix,trans_targ)
            # if 'main' function exists locally, then we'll have a collision with new main during compilation
            # renaming to 'patchmain'
            #if target == "main":
            #    #translation_dict["main"]="patchmain"
            #    detour_target="{}{}".format(detour_prefix,"patchmain")
            mainStub_t += f"\t{detour_target}(\n" 
            print("Detour target: {}:{} => {} ".format(ltarget,trans_targ,detour_target))

            args = []
            targetHeader = ""
            targetRetType = "void"
            call_me[target]="{}".format(re.sub("::","__",target))

            for f in funcs[target]:
                print(target, f)
                array = f.split("(", maxsplit=1)
                targetRetType, targetName = self.getTypeAndLabel(array[0])
                checkme=False
                targ=translation_dict.get(targetName,None)
                if target == targetName or targ:
                    checkme=True
                # this is a workaround for a weird IDA decomp output (removes '_' function prefixes)
                #if target == "main" and targetName == "patchmain":
                #    checkme=True
                #if target == "_"+targetName:
                #    checkme=True
                #    translation_dict[target]=targetName
                if checkme:
                    # print(f)
                    targetHeader = f
                    #array = f.split("(", maxsplit=1)
                    #targetRetType, targetName = self.getTypeAndLabel(array[0])
                    if len(array)<2:
                        break #no arguments
                    else:
                        argLine = array[1].strip(";")
                        idx=argLine.rfind(')')
                        if idx>=0:
                            argLine=argLine[:idx]
                        # print(f, argLine)
                        if len(argLine.strip()) <= 0:
                            break #no arguments
                        argArray = argLine.split(",")
                        #for arg in argArray:
                        j=0
                        size=len(argArray)
                        while j < size:
                            fn_ptr=False
                            print("DEBUG : {} [{}] ".format(argArray[j],j))
                            arg=argArray[j]
                            # this looks like a function pointer
                            while arg.count('(') != arg.count(')') and j+1 < size:
                                j+=1
                                arg+=","+argArray[j]
                                print("DEBUG [fnptr]: arg = '{}'".format(arg))
                                fn_ptr=True
                            arg = arg.strip()
                            argTuple = self.getTypeAndLabel(arg,fn_ptr)
                            print("DEBUG: arg = {} [{}] [argTuple = {}]".format(arg,argLine,argTuple))
                            args.append(argTuple)
                            j+=1
                        break
                    


            # we're changing detour entry s.t. it has a prefix (if it doesn't exist, get default value of target)
            # ----------------------------------------------------------------
            # pdr : translation_dict[local_function_name] = binary_symbol_name
            x1=re.search(r"\b("+ltarget+r")\b",targetHeader)
            x2=re.search(r"\b("+trans_targ+r")\b",targetHeader)
            if x1:
                print("Replacing : {} with {} in '{}'".format(ltarget,detour_target,targetHeader))
                targetHeader = re.sub(r"\b("+ltarget+r")\b",detour_target,targetHeader)
            else:
                print("Replacing : {} with {} in '{}'".format(trans_targ,detour_target,targetHeader))
                #targetHeader = targetHeader.replace(trans_targ,detour_target)
                targetHeader = re.sub(r"\b("+trans_targ+r")\b",detour_target,targetHeader)
            wrapperStub += targetHeader.split("(", maxsplit=1)[0] #remove arguments
            wrapperStub += "(\n"

            init_mainBody=""
            #print("dataMap", dataMap)
            ebx_prefix=False
            if glibc_symbols and (len(stubMap[target].keys())>0 or len(dataMap[target].keys())>0):
                mainStub_t += "\t\tNULL,\n"
                wrapperStub += "\tvoid* EBX,\n"
                init_mainBody= "\torigPLT_EBX = (unsigned int) EBX;\n"
                ebx_prefix=True
            # arguments to wrapper function
            for s in stubMap[target].keys():
                s_name=self.get_stub_name(s)
                s_name=translation_dict.get(s_name,s_name)
                mainStub_t +=  "\t\tNULL,\n" 
                wrapperStub += "\tvoid*"
                if s in self.weakFuncs:
                    wrapperStub += "*"
                wrapperStub += " my%s,\n" % s_name
                if ":" not in call_me[target]:
                    call_me[target]+=":"
                else:
                    call_me[target]+=","
                sym_name=demang2mangLUT[s_name]
                call_me[target]+=sym_name
                print(s)
                print("  - STUBNAME: ", self.get_stub_name(s),s_name,sym_name)
        
            # note from pdr: looks like when data declarations are included, the 
            # function prototype and funcstubs order of symbol definitions 
            # are not consistent
            ZERO_PARAMS=True
            for d in dataMap[target].keys():
                print("data", d)
                mainStub_t +=  "\t\tNULL,\n"
                dataDef = d.split(";")[0]
                dataDef = dataDef.split("=")[0].strip()
                dataType, dataName = self.getTypeAndLabel(dataDef)
                array_size=len(re.findall("\[\d*\]",dataName))
                if ":" not in call_me[target]:
                    call_me[target]+=":"
                else:
                    call_me[target]+=","
                if array_size>=2:
                    print("SORRY: two-dimensional array objects just aren't working right now")
                    print(" ==> "+dataType+" "+dataName)
                    wrapperStub += "// --- WARNING! Two-dimensional array objects are not yet supported"
                    wrapperStub += "\tvoid* my%s,\n" % dataName
                    call_me[target]+=dataName
                #elif array_size==1 and "*" not in dataType:
                elif array_size==1 and (("*" not in dataType) or ("*" in dataType and "[]" in dataName)):
                    dataNamex = dataName.split("[")[0] # handle arrays
                    wrapperStub += "\tvoid* my%s,\n" % dataNamex
                    call_me[target]+=dataNamex
                else:
                    wrapperStub += "\tvoid* my%s,\n" % dataName
                    call_me[target]+=dataName
                print("   - DATA DECL: ", dataName)

            for argTuple in args:
                ZERO_PARAMS=False
                argType = argTuple[0]
                argName = argTuple[1]
                if argType=="...":
                    next;
                elif "double" in argType or "float" in argType or "int" in argType:
                    mainStub_t += "\t\t(%s) 0,\n"  % argType
                else:
                    varname=f"v{len(mainStub_pre)}";
                    malloc=f"\t{argType}* {varname}=malloc(sizeof({argType}));"
                    free=f"\tfree({varname});"
                    mainStub_pre.append(malloc);
                    mainStub_post.append(free);
                    mainStub_t += f"\t\t*{varname},\n"
                wrapperStub += "\t%s %s,\n" % (argType, argName)

            if mainStub_t.rstrip().endswith(','):
                mainStub_t = mainStub_t.rstrip()[:-1]  #strip ,\n
            if wrapperStub.rstrip().endswith(','):    
                wrapperStub = wrapperStub.rstrip()[:-1]  #strip ,\n

            mainStub_t += "\n\t);\n"
            # pdr : need to move this outside of FOR loop
            #mainStub += "}\n"

            wrapperStub += "\n)\n{\n"
    
            # create ret variable if needed
            if targetRetType != "void" and targetRetType != "void __noreturn":
                wrapperStub += "\n\t%s retValue;\n\n" % targetRetType
            wrapperStub+=init_mainBody
            # body
            for d in dataMap[target].keys():
                dataDef = d.split(";")[0]
                if dataDef.startswith("//"):
                    dataDef = dataDef[3:] # handle commented out cases
                dataDef = dataDef.split("=")[0].strip()
                dataType, dataName = self.getTypeAndLabel(dataDef)
                array_size=len(re.findall("\[\d*\]",dataName))
                if array_size>=2:
                    print("// --- WARNING! Two-dimensional array objects are not yet supported\n")
                    wrapperStub += "\tp%s = (%s*) my%s;\n" % (dataName, dataType, dataName)
                    print(" // --- END OF WARNING!\n")
                #elif array_size==1 and "*" not in dataType:
                elif array_size==1 and (("*" not in dataType) or ("*" in dataType and "[]" in dataName)):
                    dataNamex = dataName.split("[")[0] # handle arrays
                    wrapperStub += "\tp%s = (%s*) my%s;\n" % (dataNamex, dataType, dataNamex)
                else:
                    wrapperStub += "\tp%s = (%s*) my%s;\n" % (dataName, dataType, dataName)
    
            for s in stubMap[target].keys():
                name = self.get_stub_name(s)
                pname=f"p{name}"
                dname=translation_dict.get(name,name)
                if name in list(VALIST_TRANSFORM.keys()):
                    name=f"{STUB_PREFIX}{name}"
                elif glibc_symbols and name in glibc_symbols or name in CSTDIO_FUNCS:
                    name=f"{STUB_PREFIX}{name}"
                wrapperStub += "\t%s = (%s) (" % (name, pname) 
                if s in self.weakFuncs:
                    wrapperStub += "*"
                wrapperStub += "my%s);\n" % (dname)
    
            numStubs = len(stubMap[target])
            numFuncArgs = len(args)
    
            wrapperStub += "\n\t__prd_init();\n"
    
    
            wrapperStub += "\t"
    
            if targetRetType != "void" and targetRetType != "void __noreturn":
                wrapperStub += "retValue = "
    
            # call target:
    
            # we're renaming the detour entry function and the decompiled function
            # previous: <orig_fn> [detour entry] ; my<orig_fn> [decompiled function]
            # new : <detour_prefix><orig_fn> [detour entry] ; <orig_fn> [decompiled function]
            # there's a weird behavior with IDA, it translates functions prepended with '_' to without
            #wrapperStub += "my%s(\n" % target
            #wrapperStub += "%s(\n" % target
            wrapperStub += "%s(\n" % ltarget
    
            for argTuple in args:
                argName = argTuple[1]
                wrapperStub += "\t\t%s,\n" % (argName)
    
            if args: # list not empty
                wrapperStub = wrapperStub[:-2]  #strip ,\n
    
            wrapperStub += "\n\t);\n"
    
            wrapperStub += "\n\t__prd_exit();\n"
    
            # asm
            #t="patchmain" if target=="main" else target
            wrapperStub += "\n\t /* ASM STACK "+ltarget+" HERE */\n"
    
            # wrapperStub += "\n\tasm(\n"
    
            # wrapperStub += "\t\"nop\\n\\t\"\n\t\"nop\\n\\t\"\n\t\"nop\\n\\t\"\n\t\"nop\\n\\t\"\n"
            # wrapperStub += "\t\"add $0x%x,%%esp\\n\\t\"\n" % (numFuncArgs * 4)
            # wrapperStub += "\t\"pop %ebx\\n\\t\"\n"
            # wrapperStub += "\t\"pop %ebp\\n\\t\"\n"
            # wrapperStub += "\t\"pop %ecx\\n\\t\"\n"
            # wrapperStub += "\t\"add $0x%x,%%esp\\n\\t\"\n" % (numStubs * 4)
            # wrapperStub += "\t\"push %ecx\\n\\t\"\n"
            # wrapperStub += "\t\"ret\\n\\t\"\n"
    
            # wrapperStub += "\t);\n"        
    
            # ret and close
            wrapperStub += "\n\treturn"
            if targetRetType != "void" and targetRetType != "void __noreturn":
                wrapperStub += " retValue"
            wrapperStub += ";\n}\n\n"


        # print("---------- MAIN STUB -------------")
        # print(mainStub)
        # print("---------- wrapperStub -------------")
        # print(wrapperStub)

        # pdr : move this to outside of FOR loop
        if len(mainStub_pre)>0:
            mainStub = "\n#include <stdlib.h>\n"+mainStub;
        mainStub += "\n".join(mainStub_pre)+"\n";
        mainStub += mainStub_t;
        mainStub += "\n".join(mainStub_post)+"\n";
        mainStub += "\treturn 0;\n"
        mainStub += "}\n"

        return  wrapperStub + "\n\n" + mainStub, call_me



class Formatter:

    def __init__(self):
        pass

class GenprogDecomp:

    def __init__(self, target_list_path, scriptpath, ouput_directory,entryfn_prefix,r2ghidra=None,strip=False,decompdir="/tmp/decomp",use_new_features=False):
        self.use_new_features=use_new_features
        self.target_list_path = target_list_path
        self.scriptpath = scriptpath
        self.ouput_directory = ouput_directory
        self.decompdir = os.path.abspath(decompdir)
        self.detour_entry_fn_prefix=entryfn_prefix
        self.dem2mangLUT=None
        self.mang2demLUT=None
        self.r2ghidra_cmd=r2ghidra
        print(f"Strip Binary = {strip}",flush=True)
        print(f"Target File = {self.target_list_path}",flush=True)
        self.strip=strip

    def get_decompilations(self,symlist,binp):
        syms=" ".join(symlist)
        cmd=self.r2ghidra_cmd
        cmd=re.sub("<SYM>",syms,cmd)
        cmd=re.sub("<BIN>",binp,cmd)
        d=subprocess.check_output(cmd,shell=True)
        decomp=d.decode('ascii').rstrip()
        return decomp

    def get_r2ghidra_out(self,symbol,binp,decompdir:str):
        decompf=f"{decompdir}/{symbol.strip()}-ghidra.c"
        decomp=None
        if not os.path.exists(decompf) or (os.stat(decompf).st_size==0):
            cmd=self.r2ghidra_cmd
            cmd=re.sub("<SYM>",symbol,cmd)
            cmd=re.sub("<BIN>",binp,cmd)
            d=subprocess.check_output(cmd,shell=True)
            decomp=d.decode('ascii').rstrip()
            with open(decompf, "w") as decompFile:
                decompFile.write(decomp)
                decompFile.close()
        else:
            with open(decompf, "r") as decompFile:
                decomp = decompFile.read()
                decompFile.close()
        return decomp


    def get_symbols(self,binary_path,workdir):
        symbol_info=os.path.join(workdir,"symbol_info.pkl")
        symbol_dict=None
        if os.path.exists(symbol_info) and os.path.getsize(symbol_info)>0:
            x=readpickle(symbol_info)
            symbol_dict=x['symbol_dict']
            if not self.mang2demLUT:
                self.mang2demLUT=dict() 
            self.mang2demLUT.update(x['mang2demLUT'])
            if not self.dem2mangLUT:
                self.dem2mangLUT=dict()
            self.dem2mangLUT.update(x['dem2mangLUT'])
        else:
            cmd=["/usr/bin/nm",binary_path]
            #cmd=["/usr/bin/nm","--demangle",binary_path]
            symproc=subprocess.Popen(" ".join(cmd),stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=True)
            #ret=symproc.poll()
            #if ret == None:
            #    ret=symproc.poll()
            #    print("Error running '{}' {} ".format(" ".join(cmd),ret))
            #    return None
            sout,serr = symproc.communicate()
            output=sout.decode('ISO-8859-1')
            lines=output.split('\n')
            symbol_dict = dict()
            count=0;MAX=len(lines)
            for x in lines:
                if (count==len(lines) or (count%int(MAX/10))==0):
                    print(f"{count}/{len(lines)} completed")
                count+=1
                if len(x)<12:
                    #print(x)
                    continue
                symadd=x[0:8]
                symtype=x[9:10]
                full_symname=x[11:len(x)]
                if x[8]!=" ":
                    print("ERROR!! Looks like a 64b binary\nExiting.")
                    import sys;sys.exit(-1)
                symname=full_symname
                is_glibc="GLIBC" in symname
                if is_glibc:
                    symname=x[11:len(x)].split('@',1)[0]
                ltype=symbol_dict.get(symtype,None)
                if not ltype:
                    symbol_dict[symtype]=list()
                cmd=["/usr/bin/c++filt",symname]
                demangled = subprocess.check_output(" ".join(cmd),shell=True).decode('ascii').rstrip()
                clean=demangled.split('(',1)[0]
                symbol_dict[symtype].append({'name':clean,'fullname':demangled,'mangled':symname,'address':symadd,'type':symtype,'is_glibc':is_glibc})
                if not self.mang2demLUT:
                    self.mang2demLUT=dict() 
                if not self.dem2mangLUT:
                    self.dem2mangLUT=dict()
                self.mang2demLUT[symname]=(clean,demangled)
                self.dem2mangLUT[clean]=symname
            
            x={'symbol_dict':symbol_dict,'mang2demLUT':self.mang2demLUT,'dem2mangLUT':self.dem2mangLUT}
            writepickle(symbol_info,x)

        print("Completed get_symbols",flush=True);
        return symbol_dict

    def get_target_info(self,workdir):
        self.targets=list()
        with open(self.target_list_path, "r") as targetFile:
            for line in targetFile:
                if len(line)<=0:
                    continue
                else:
                    print(line,flush=True)
                finalOutput = ""
                dataMap=dict()

                target, path, funcs = line.rstrip().split(",")
                target = target.strip()
                path = path.strip()
                symbols_lut = self.get_symbols(path,os.path.join(workdir,target))
                #print(f" => {','.join(self.mang2demLUT.keys())}",flush=True)
                funcs_=re.sub("::","_____",funcs)
                funcs_=re.sub(":"," ",funcs_)
                funcs=re.sub("_____","::",funcs_)
                # we're now assuming that we're getting mangled symbols as input
                funcList = funcs.split(" ")
                print(f"FUNCLIST='{funcList}'",flush=True)
                for i in funcList:
                    print(f"{i} ",flush=True)
                    print(f" => {self.mang2demLUT[i]}",flush=True)
                detour_funcs= [ (self.mang2demLUT[f],f) for f in funcList ]
                x={'target':target,'path':path,'funcList':funcList,'detour_funcs':detour_funcs,'symbols_lut':symbols_lut}
                self.targets.append(x)
        targetFile.close()

    def find_symbol(self,demangled:str):
        search_re=re.compile(r"\b"+f"{demangled}"+r"\b")
        for dm in self.dem2mangLUT.keys():
            if search_re.match(dm):
                return self.dem2mangLUT[dm]
        return None

    def run(self):
        idaw = IDAWrapper(self.scriptpath)
        cleaner = CodeCleaner()
        functions = []
        success = []
        failure = []
        decomp_failure_count=0
        for TARG in self.targets:
            target=TARG['target']
            path=TARG['path']
            funcList=TARG['funcList']
            detour_funcs=[x[0][0] for x in TARG['detour_funcs']]
            detour_fullfuncs=[x[0][1] for x in TARG['detour_funcs']]
            detour_syms=[x[1] for x in TARG['detour_funcs']]
            symbols_lut = TARG['symbols_lut']
            binpath=path
            decompile_error_count=0
            if self.strip:
               binpath=strip_binary(path) 

            outdir = os.path.join(self.ouput_directory, target)
            decompdir = os.path.join(self.decompdir, target)
            if not os.path.exists(outdir):
                os.makedirs(outdir)
            if not os.path.exists(decompdir):
                os.makedirs(decompdir)

            finalOutput = ""
            dataMap=dict()
            detfncs=detour_funcs+[x[1:] for x in detour_funcs if x.startswith('_') ]
            detours_regex="|".join(detfncs)

            while len(detours_regex)>0 and detours_regex[-1]=='|':
                detours_regex=detours_regex[0:-1]
            detours_re=re.compile(r"\b("+detours_regex+r")\b")
            mainFunc = funcList[0].strip()

            print("="*100,flush=True)
            print("Decompile and Recompiling: %s in target %s" %(str([x for x in detour_funcs]), target),flush=True)
            print("="*100,flush=True)

            print("    --- Getting typedef mappings...",flush=True)
            structDump = idaw.get_typedef_mappings(binpath,decompdir,self.use_new_features)
            # print(structDump)
            typedefLines = cleaner.remove_artifacts(structDump,self.use_new_features)
            needs_stdio=False
            typehdr="resolved-types.h"
            if self.use_new_features:
                stdio_types=CHDR_TYPES
                typedefLines,types_used,needs_stdio = cleaner.resolve_type_order(typedefLines,decompdir)

            else:
                typedefLines = cleaner.cleanup_typedefs(typedefLines)
                finalOutput += typedefLines

            print("    --- Decompiling target functions...",flush=True)
            data_symbols = [ x['name'] for s in ['d','D','b','B'] for x in symbols_lut[s] ]
            fn_symbols = [ x['name'] for s in ['t','T','U','w','W'] for x in symbols_lut[s] ]
            glibc_symbols = [ x['name'] for s in ['t','T','U','w','W'] for x in symbols_lut[s] if x['is_glibc'] and (x['name'] not in CSTDIO_DATASYMS)]
            finalOutput += cleaner.generate_det_placeholders()

            fulldecomp_code=""
            stubs={'prototypes':list(),'symbols':list(),'external':list(),'nm_names':list(),'is_glibc':list()}
            funcHeaders={'prototypes':list(),'symbols':list(),'external':list(),'nm_names':list(),'is_glibc':list()}
            decls=[[],[],[],[],[],[]]
            header_decls=decls[0]
            func_decls=decls[1]
            data_decls=decls[2]
            decomp_decls=decls[3]
            decomp_defs=decls[4]
            stubs_per_func=dict()
            funcHeaders_per_func=dict()
            decomp_per_func=dict()
            dataMap_per_func=dict()
            translate_dict=dict()
            fn_info=dict()
            data_decls.append("\n//"+"-"*68)
            data_decls.append(IDA_DATA_START+"\n")
            func_decls.append("\n//"+"-"*68)
            func_decls.append(IDA_STUB_START+"\n")
            decomp_defs.append("\n//"+"-"*68)
            decomp_defs.append("// Decompiled Functions\n")
            sym_requirements=dict()
            dataRemoveList=list()

            #decompFH=open("/tmp/decomp_raw.c","w")
            guessed_protos=set()
            for idx,funcsym in enumerate(funcList):
                func=funcsym
                if self.mang2demLUT:
                    func=self.mang2demLUT[funcsym][0]
                print(f"Processing Function: {func} [symbol = '{funcsym}']")
                decomp_code = idaw.decompile_func(binpath, funcsym,decompdir)
                decomp_code = re.sub(r"\bmain\b","patchmain",decomp_code)
                if func not in fn_symbols:
                    print(f"{func} not in {fn_symbols}")
                    print("invalid function symbol, skipping...")
                    failure.append((target, binpath, funcsym))
                    continue
                print(f"STUBS_PER_FUNC[ID] : ID={detour_funcs[idx]}")
                stubs_per_func[detour_funcs[idx]]=dict()
                funcHeaders_per_func[detour_funcs[idx]]=dict()
                if len(decomp_code) <= 0:
                    print("decompilation error, skipping...")
                    decompile_error_count+=1;failure.append((target, binpath, funcsym))
                    continue

                decomp_code = cleaner.remove_artifacts(decomp_code,self.use_new_features)
                #print(decomp_code)

                print("    --- Creating stubs...")
                #      dataMap [per fun] ; dataMap_ [global]
                #return dataMap, removeList, dataMap_, dataLines_
                dataMap, dataRemoveList, d, data_decls = cleaner.get_data_declarations(decomp_code,data_symbols,dataMap, data_decls)
                known_hexray_issue = [ x for x in d['local_vars'] if "dword" in x ]
                #if len(known_hexray_issue)>0 and self.r2ghidra_cmd:
                if self.r2ghidra_cmd:
                    print(f"KNOWN HEX RAY ISSUE: {known_hexray_issue}")
                    issue_regex=r"&("+"|".join(known_hexray_issue)+r")\b"
                    issue_re=re.compile(issue_regex)
                    if issue_re.search(decomp_code):
                        # need unstripped binary for input
                        new_decomp= self.get_r2ghidra_out(funcsym,path,decompdir)
                        print(f"r2ghidra decompiled code: {new_decomp}")
                        print(f"prev decompiled code: {decomp_code}")
                        decomp_code=re.sub(r"\b__thiscall\n",r"",new_decomp)
                # d = {'prototypes':dict(),'sym2proto':dict(),'ext_vars':set(),'local_vars':set()} 
                #data_syms={'ext_var':ext_var_syms,'local_var':local_var_syms}
                dataMap_per_func[detour_funcs[idx]]=d
                # stubs are the Function declaration section content [external and local function prototypes]
                # funcHeaders are the local function definitions
                guessed_protos |= set(cleaner.get_guessed_funcs(decomp_code))
                stubs, funcHeaders, h, s, f, d, g, translate_dict,rm_decomp_decl = cleaner.get_stubs(decomp_code,stubs,funcHeaders,detours_re,
                    decomp_decls,fn_symbols,glibc_symbols,data_symbols,
                    translate_dict,guessed_protos,decomp_decls)
                decomp_per_func[detour_funcs[idx]]=h[d:-1]
                #return stubs, funcs, fulldecomp, lstubs, lfuncs, fn_start,global_fns
                header_decls+=h
                print("DATA REMOVE LIST '{}' => {}".format(func,dataRemoveList))
                print("GLOBAL DATA MAP '{}' => {}".format(func,dataMap))
                print("DATA DECLS '{}' => {}".format(func,data_decls))
                print("FUNCTION DATA MAP '{}' => {}".format(func,d))
                print("STUB DECLARATIONS '{}' => {}".format(func,stubs['prototypes']))
                print("NEW STUB DECLARATIONS '{}' => {}".format(func,s['prototypes']))
                print("NEW FUNCTION DECLARATIONS '{}' => {}".format(func,g))
                print(f"DETOUR FUNCS 'detour_funcs[{idx}]' => '{detour_funcs[idx]}'")
                print(f"GUESSED FUNCS: {guessed_protos}")
                
                for rmdd in rm_decomp_decl:
                    print(f"Removing existing weaker conflicting declaration: {rmdd}")
                    del decomp_decls[decomp_decls.index(rmdd)]
                decomp_decls+=g
                stubs_per_func[detour_funcs[idx]]=s
                funcHeaders_per_func[detour_funcs[idx]]=f['prototypes']
                #fulldecomp_code += decomp_code

            #decompFH.close()
            func_decls=stubs['prototypes']
            decomp_defs=[]
            for i in decomp_per_func.keys():
                decomp_defs.extend(decomp_per_func[i])

            if decompile_error_count == len(funcList):
                decomp_failure_count+=1
                continue
            
            # let's collect basic decompiler output before any transformation
            basic_=[]
            basic_+=["\n","//"+'-'*68,"// Function Prototypes"]+func_decls+["\n"]
            basic_+=["\n","//"+'-'*68,"// Decompiled Variables"]+data_decls+["\n"]
            basic_+=["\n","//"+'-'*68,"// Decompiled Function Declarations"]+decomp_decls+["\n"]
            basic_+=["\n","//"+'-'*68,"// Decompiled Function Definitions"]+decomp_defs+["\n"]
            basic_finalOutput="\n\n"+"\n".join(basic_)+"\n\n"

            #let's clean-up the GLIBC references to avoid collision
            decomp_defs = cleaner.prevent_glibc_collision(decomp_defs,CSTDIO_FUNCS+glibc_symbols)

            # let's uniquify the header lines by the set datatype
            print("\nFUNC_HEADERS:\n{}".format(" -- "+"\n -- ".join(funcHeaders['prototypes'])))
            print("\nDATA_DECLS:\n{}".format(" -- "+"\n -- ".join(data_decls)))
            print("\nFUNC_DECLS:\n{}".format(" -- "+"\n -- ".join(func_decls)))
            print("\nDECOMP_DECLS:\n{}".format(" -- "+"\n -- ".join(decomp_decls)))
            print("\nDECOMP_DEFS:\n{}".format(" -- "+"\n -- ".join(decomp_defs)))

            # replacing data declarations with the defines
            data_decls = cleaner.replace_data_defines_list(data_decls, dataMap, dataRemoveList)

            full_=[]
            if self.use_new_features:
                full_+=["\n","//"+"-"*68,"// EBX mechanism needed to interface with original binary's PLT","\n",
                    "unsigned int preEBX = NULL;","unsigned int origPLT_EBX = NULL;","\n"]

            full_+=header_decls[0:6]+["\n","//"+"-"*68,"// Function Declarations","\n"]
            full_+=func_decls+["\n"]
            full_+=["\n","//"+'-'*68,"// Decompiled Variables"]+data_decls+["\n"]
            full_+=["\n","//"+'-'*68,"// Decompiled Function Declarations"]+decomp_decls+["\n"]
            full_+=["\n","//"+'-'*68,"// Decompiled Function Definitions"]+decomp_defs+["\n"]
            #finalOutput+="\n\n"+"\n".join(header_decls[0:6]+func_decls+data_decls+decomp_decls)+"\n\n"
            decomp_finalOutput="\n\n"+"\n".join(full_)+"\n\n"
            # this following line replaces content in parts of the code we don't want
            #finalOutput = cleaner.replace_data_defines(finalOutput, dataMap, dataRemoveList)
            stubMap_=dict()
            nonCGCList_=dict()
            updated_stubs,updated_dataMap,nm2decomp_syms=cleaner.resolve_dependencies(stubs_per_func,dataMap_per_func)

            print(f"GLIBC SYMBOLS => {glibc_symbols} ({type(glibc_symbols)})")
            stubMap, nonCGCList= cleaner.make_pcgc_stubs(stubs, funcHeaders['prototypes'],glibc_symbols if self.use_new_features else None)
            for f in detour_funcs:
                #stubMap_[f], nonCGCList_[f] = cleaner.make_pcgc_stubs(stubs_per_func[f],funcHeaders_per_func[f])
                #print(f"f=>{f}")
                #print(f"updated_stubs=>{updated_stubs}")
                #print(f"updated_stubs[f]=>{updated_stubs[f]}")
                stubMap_[f], nonCGCList_[f] = cleaner.make_pcgc_stubs(updated_stubs[f],funcHeaders['prototypes'],glibc_symbols)
            # finalOutput = cleaner.remove_nonCGC_calls(finalOutput, nonCGCList)
            decomp_finalOutput = cleaner.replace_stubs(decomp_finalOutput, stubMap)
            # pdr update - let's not rename the functions
            # finalOutput = cleaner.rename_target(finalOutput, mainFunc)
                    

            print("    --- Additional cleaning")                
            decomp_finalOutput = cleaner.handle_const_assigns(decomp_finalOutput, funcHeaders)


            print("    --- Generating wrappers...")
            # we just don't want mainFunc, we want all detoured functions
            footer,detfn_defs = cleaner.generate_wrapper(detour_funcs, funcHeaders_per_func, stubMap_, updated_dataMap, self.detour_entry_fn_prefix,translate_dict,self.dem2mangLUT,glibc_symbols if self.use_new_features else None)

            decomp_finalOutput += footer

            decomp_finalOutput = re.sub("::","__",decomp_finalOutput)
            header = ""
            header += "#include \"defs.h\"\n"
            if self.use_new_features:
                basic_finalOutput=f"#include \"defs.h\"\n#include \"{typehdr}\""+basic_finalOutput
                header += f"#include \"{typehdr}\"\n"
                typedefLines = re.sub("::\$","__E__",typedefLines)
                typedefLines = re.sub("::","__",typedefLines)
                basic_finalOutput=re.sub("::","__",basic_finalOutput)
                if self.strip:
                    basic_finalOutput=cleaner.transform_cpp(basic_finalOutput)
                else:
                    basic_finalOutput=cleaner.transform_std(basic_finalOutput)

            header += "\n// Auto-generated code for recompilation of target [%s]\n\n" % target
            finalOutput = header + finalOutput + decomp_finalOutput
            if self.strip:
                finalOutput=cleaner.transform_cpp(finalOutput)
            else:
                finalOutput=cleaner.transform_std(finalOutput)


            print("Recompilation Complete!")

            print("\nWriting to ", outdir)
                
            outpath = os.path.join(self.ouput_directory, target, target+"_recomp.c")
            with open(outpath, "w") as outFile:
                outFile.write(finalOutput)
            outFile.close()

            if self.use_new_features:
                print(f"WRITING TYPES TO {self.ouput_directory}/{target}/{typehdr}")
                with open(os.path.join(self.ouput_directory,target,typehdr),'w') as f:
                    f.write(typedefLines)
                    f.close()
                    print(f"DONE WRITING TO {self.ouput_directory}/{target}/{typehdr}")
                outpath = os.path.join(self.ouput_directory, target, "basic.c")
                with open(outpath,"w") as of:
                    of.write(basic_finalOutput)
                    of.close()
            
            success.append((target, binpath, funcList))

            #funcStubline = ""
            #for stubLine in stubMap.keys():
            #    stubName = cleaner.get_stub_name(stubLine)
            #    funcStubline += stubName +","
            #
            #for dataStub in dataMap.values():
            #    # IPython.embed()
            #    dataDef = dataStub.split("\n")[1]
            #    dataName = dataDef[8:].split(maxsplit=1)[0]
            #    funcStubline += dataName +","
            #funcStubline = funcStubline.strip(",")
            funcStubs = [f for f in detfn_defs.values()]
            print(f"funcStubs: {funcStubs}")
            funcStubline = re.sub('\[\d*\]',""," ".join(funcStubs))
            print(f"funcStubline: {funcStubline}")
            detours = []
            cleanup_detfn_defs=dict()
            for i,x in detfn_defs.items():
                upd_x=re.sub(r"\[\d+\]","",x)
                cleanup_detfn_defs[i]=upd_x
                di=re.sub("::","__",i)
                sym_i=self.dem2mangLUT[i]
                define=f"{di}:{sym_i}"
                if self.detour_entry_fn_prefix:
                    di="{}{}".format(self.detour_entry_fn_prefix,i)
                    di=re.sub("::","__",di)
                    define="{}:{}".format(di,sym_i)
                elif i=="main":
                    di="patchmain"
                    define="{}:{}".format(di,sym_i)

                if i=="main":
                    define+="+7"
                detours.append(define)

            
            #detour_list=[ str(f+":"+self.detour_entry_fn_prefix+f) for f in detour_funcs ]
            makefile_dict={
            "BIN":target,
            "MYSRC":target+"_recomp.c",
            "MYREP":"repair.c",
            "DETOUR_PREFIX":self.detour_entry_fn_prefix,
            "DETOURS":detours,
            #"FUNCSTUB_LIST":[ "{}:{}".format(f,funcStubline) for f in detour_funcs ]
            "FUNCSTUB_LIST": cleanup_detfn_defs
            }
            # pdr: should really put this in in a separate configuration parsing 
            #      and generation script/program
            funcinsert_call="\n"
            if self.use_new_features:
                funcinsert_call="--plt-ebx-support"
            makefile_target_info = "# Auto-generated Makefile include file\n"  + \
                          "BIN := " + target + "\n" + \
                          "DETOUR_BIN ?= $(BIN).trampoline.bin\n" + \
                          "MYSRC ?= " + target+"_recomp.c" + "\n" + \
                          "MYREP ?= " + "repair.c" + "\n" + \
                          "DETOUR_PREFIX := " + self.detour_entry_fn_prefix + "\n" + \
                          "DETOUR_DEFS := " + funcStubline + "\n" + \
                          "DETOUR_CALLS := $(patsubst %, --external-funcs $(DETOUR_PREFIX)%, $(DETOUR_DEFS))\n" + \
                          "DETOURS := " + " ".join(detours) + "\n" + \
                          "FUNCINSERT_PARAMS := $(DETOURS) $(DETOUR_CALLS) --debug "+funcinsert_call 
                          #"FUNCINSERT_PARAMS := --detour-prefix $(DETOUR_PREFIX) $(DETOURS)\n" 
            #if self.strip:
            #    makefile_target_info += "\n## Symbols are mangled, indicating CPP code.\n"+\
            #              "# overriding DIET_GCC to be diet_g++ script\n"+\
            #              "DIET_GCC?=${DIET32PATH}/diet_g++\n"

            #newfuncStubline = ""
            #for f in detour_funcs:
            #    newfuncStubline += f+":"+funcStubline+"\n"
            #funcStubline = newfuncStubline
            print("FUNC_STUBS:\n"+funcStubline)
            outpath = os.path.join(self.ouput_directory, target, target+"_funcstubs")
            makefile_include_outpath = os.path.join(self.ouput_directory, target, "prd_include.mk")
            json_outpath = os.path.join(self.ouput_directory, target, "prd_info.json")
            with open(makefile_include_outpath, "w") as outFile:
                outFile.write(makefile_target_info)
            outFile.close()
            with open(outpath, "w") as outFile:
                outFile.write(funcStubline)
            outFile.close()
            import json
            with open(json_outpath, 'w') as outFile:
                json.dump(makefile_dict,outFile)
            outFile.close()

            print("="*100)

            shutil.copyfile(DEFS_PATH, os.path.join(outdir, "defs.h"))

            # break
            # mappings = idaw.get_typedef_mappings(path)

        print(" ALL TARGETS COMPLETE")
        print(" --- %d binaries successesful recompiled" % len(success))
        for s in success:
            print("     - ", s)
        print(" --- %d binaries failed" % len(failure))
        for f in failure:
            print("     - ", f)
        print("="*100)
        if decomp_failure_count>0:
            import sys;sys.exit(-1)




def main():
    if not os.path.isfile(IDA_PATH):
        print("ERROR: Environmental variable IDA_BASE_PATH is not set or '"+IDA_DEFAULT_PATH+"' does not exist")
        import sys
        sys.exit(-1)
    parser = argparse.ArgumentParser(description='')
    parser.add_argument('--decompdir',dest='decompdir',default="/tmp/decomp",action='store',
                        help='path to store raw decompiled content')
    parser.add_argument('--detour-prefix',dest='detfn_prefix',action='store',default="det_",
                        help='Detour prefix to append to detour entry function')
    parser.add_argument('target_list',
                        help='path to the list of target binaries + paths')
    parser.add_argument("--strip-binary",dest='strip',
                        default=False,action='store_const',const=True,
                        help='get decompiled output from stripped version of binary')
    parser.add_argument('ouput_directory',
                        help='path to output directory')
    parser.add_argument('--scriptpath', default="get_ida_details.py",
                    help='path to idascript')
    parser.add_argument('--use-new-features', dest='version2',
                    default=False,action='store_const',const=True,
                    help='Use the new features [type order resolution and pltebx]')
    parser.add_argument('--r2ghidra', dest='r2',default=None,
                    help='r2ghidra command line <SYM> is symbol to decompile, <C_OUT> is decompile out file')

    args, unknownargs = parser.parse_known_args()
    if not os.path.exists(args.decompdir):
        os.makedirs(args.decompdir) # make sure that the decomp dir exists before using it
    gpd = GenprogDecomp(args.target_list, args.scriptpath, args.ouput_directory,args.detfn_prefix,args.r2,args.strip,args.decompdir,args.version2)
    gpd.get_target_info(args.decompdir)
    gpd.run()

main()


# idascript line
# htay@htay-OptiPlex-7070:~/genprog_decomp/tests$ ~/ida-7.1/idat -Ohexrays:-nosave:ascii_test:cgc_WalkTree -A ASCII_Content_Server
