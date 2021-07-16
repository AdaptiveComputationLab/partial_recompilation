import os
import subprocess
import IPython
import argparse
import tempfile
import re
import shutil
import time
import random

# path to idat binary

IDA_DEFAULT_PATH=os.environ['HOME']+"/seclab_ida/ida/idat"
if os.environ['IDA_BASE_DIR']:
    IDA_PATH=os.environ['IDA_BASE_DIR']+"/idat"
else:
    IDA_PATH=IDA_DEFAULT_PATH

# path to defs.h
DEFS_PATH=os.path.dirname(os.path.realpath(__file__))+"/refs/defs.h"

# stub markers for processing

IDA_STUB_START = "// Function declarations"
IDA_DATA_START = "// Data declarations"
IDA_DECOMP_START = "//----- ("
IDA_SECTION_END = "//-----"
IDA_WEAK_LABEL = "; weak"

TYPEDEF_START = "============================== START =============================="
TYPEDEF_END = "============================== END =============================="

# tags for primitives for replacement

PRIMITIVES = ["int", "long", "short", "char", "void", "double", "float", "long",
              "unsigned int", "unsigned long", "unsigned short", "unsigned char", "void", "long double"]

class IDAWrapper:
    def __init__(self, typedefScriptPath):
        self.typedefScriptPath = typedefScriptPath

    # get initial decompiled output of ida hexrays
    def decompile_func(self, binary_path, func:str):
        outname = "/tmp/"+func.strip()
        #for func_name in func_list:
        #    funcs += func_name.strip() + ":"
        #funcs = funcs[:-1] #trim dangling ':'

        # ida run command
        ida_command = [IDA_PATH, "-Ohexrays:-nosave:"+outname+":"+func, "-A", binary_path]
        print("Running: ", " ".join(ida_command),flush=True)
        subprocess.run(ida_command)

        functionLines = ""
        if not os.path.exists(outname+".c"):
            print("    !!! ERROR DECOMPILING FILE", outname+".c")
            return ""

        with open(outname+".c", "r") as decompFile:
            functionLines = decompFile.read()
        decompFile.close()
        os.remove(outname+".c")

        # print("="*30, "DECOMPILATION OUTPUT", "="*30)
        # print(functionLines)
        # print("="*70)
        print("[COMPLETED] Running: ", " ".join(ida_command))

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

        # print("="*30, "DECOMPILATION OUTPUT", "="*30)
        # print(functionLines)
        # print("="*70)

        return functionLines

    # # given a decompiled ida string, find all func calls in that string

    # get all typedef mappings
    def get_typedef_mappings(self, binary_path):
        typedefMap = dict()
        ida_command = [IDA_PATH, '-B', '-S'+"\""+self.typedefScriptPath+"\"", "-A", binary_path]
        tmpName = ""
        with tempfile.NamedTemporaryFile(mode="r", dir="/tmp", prefix="prd-ida-",delete=True) as tmpFile:
            print("RUNNING: ", " ".join(ida_command))
            env = os.environ
            env["IDALOG"] = tmpFile.name
            sp = subprocess.run(ida_command, env=env)

            typedefs = tmpFile.read()
            tmpName = tmpFile.name
            print("    -> Temp File Name:", tmpName)

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
                structDump += line

        print("FINISHED RUNNING")
        return structDump


class CodeCleaner:
    def __init__(self):
        self.weakFuncs = []

    def getTypeAndLabel(self, header, fn_ptr=False):
        if ")" in header and "((aligned(" not in header and "()" not in header and not fn_ptr:
            array = header.rsplit(")", maxsplit=1)
            hType = array[0].strip()+")"

        elif fn_ptr:
            htype = "void *"
            func_ptr_name=re.match("\w+\s+\(\*(\w+)\)",header)
            print("DEBUG : getTypeAndLabel {} => {}".format(header,func_ptr_name.group(1)))
            return htype,func_ptr_name.group(1)

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
        
    def is_function_prototype(self,argType):
        func=re.match("((struct\s+)?\w+)\s+\*?(\(\*\w+\)|\w+)\((.*)\)",argType)
        types=[]
        ret=False
        if func:
            print("Function: "+argType)
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
        print("    > RUNNING FIRSTPASS")
        lineDump = ""
        for line in structDump.splitlines():
            if "{" not in line and "}" not in line:
                if line.count(";") > 1:
                    line = line.strip()
                    line = line.replace(";", ";\n")
            lineDump += line+"\n"
        return lineDump

    def typedef_secondpass(self, structDump):
        print("    > RUNNING SECOND PASS")
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

                print("  << read line ", line)
                typedefMap[orig] = (newVal, line)
            elif line.startswith("struct ") or line.startswith("union "):
                elements = line.strip().split(maxsplit=1)
                header = elements[0].strip()
                array = elements[1].split("{", maxsplit=1)
                structDec = header+" "+array[0].strip()
                structName = structDec.rsplit(maxsplit=1)[1]
                print("  << read struct [%s] == %s" % (structName, structDec))
                structMap[structName] = structDec
                if structDec not in typedefMap.keys():
                    typedefMap[structDec] = (structName, line)

        for line in structDump.splitlines():
            if "Elf" in line:
                continue #skip

            if line.strip():
                print("  !! Processing line ", line)
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
                        print("   - Check for use of %s, originally [%s]" % (newVal, origName))
                        # print("     argline [[%s]] " % argLine)
                        typedefLine = typedefTuple[1]
                        escapedNewVal = re.escape(newVal)
                        matches = re.findall("[\\(\\{\\)\\}\\;\\,][\s]*"+escapedNewVal+"[\\(\\{\\)\\}\\;\\,\s]+", argLine)
                        for match in matches:
                            if origName in structMap.keys():
                                origName = structMap[origName]
                            if origName not in done:
                                newLine = match.replace(newVal, origName)
                                # print("      - replacing %s >> %s" % (match, newLine))
                                # print("      - original: ", line)
                                line = line.replace(match, newLine)

                        if matches:
                            print("      Associating %s with %s" % (typedefLine, line))
                            done.add(origName)
                            # substituteMap[typedefLine] = line
                        # break

            lineDump += line+"\n"

        # print("Done, processing replacement structs")

        return lineDump


    def typedef_lastpass(self, structDump):
        definitions = ""
        for line in structDump.splitlines():
                defLine = ""

                if line.startswith("typedef"):
                    defLine = line
                    # print("    ---> ", defLine)
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
                    # print("STRUCT: ", line)
                    line = line.strip(";") # prune out ending semicolon
                    header = line.split("{")[0].strip()
                    typeName = header.rsplit(maxsplit=1)[1].strip() # get name, drop struct prefixes

                    
                    matches = re.findall("[\\(\\{\\;][\s]*"+typeName+" ", line)
                    for match in matches:
                        newLine = match.replace(typeName, header)
                        line = line.replace(match, newLine)
                    defLine = "typedef "+line+" "+typeName+";"
                    print("    ---> ", defLine)

                definitions += defLine+"\n"
        return definitions

    def process_one_defline(self, definitions, line, waitingStructs, defined, forward_declared, typeDefMap):
        print("   CHECKING: ", line)

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
                # print(argString)
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

        # print("    - typeName [%s] args [%s]" % (typeName, argString))
        if typeName in defined:
            print("    - Already Processed!")
            return definitions, rearranged

        if argString:
            args = self.get_struct_args(argString)
            # print("ARGSTRING", argString)
            # print(args)
            for argTypeRaw, argName, argOrig in args:
                isfunc,type_labels = self.is_function_prototype(argTypeRaw)
                if not isfunc:
                    argType = self.get_typebase(argTypeRaw)
                    argTypeArray = argType.strip().rsplit(maxsplit=1)
                    # print(argTypeArray)
                    if len(argTypeArray) > 1:
                        type_labels = [ argTypeArray[-1] ]
                    else:
                        type_labels = [ argTypeArray[0] ]
                    # print("    --> baseType %s" % (argTypeLabel))
                    # print("    --> typeName   %s" % (typeName))
                    # print("      - defined: ", defined)
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
                            print("    --> unresolved type", argTypeLabel)
                            print("         ", forward_declared, (argTypeLabel in forward_declared))
                            print("        %s || %s" % (line, argTypeRaw))
                            # print("        defined: ", defined)


        if resolved:
            print("    !! DEFINED", typeName)
            defined.append(typeName)
            definitions += line+"\n"


            if typeName in waitingStructs.keys():
                print("   !--> RESOLVING: ", typeName)
                lines = waitingStructs[typeName]
                waitingStructs.pop(typeName)
                for line, argTypeLabel, argTypeRaw in lines:
                    print("    - Recursive process", typeName)
                    definitions, child_rearranged = self.process_one_defline(definitions, line, waitingStructs, defined, forward_declared, typeDefMap)
                    if not resolved or child_rearranged:
                        rearranged = True
                print("        - RESOLVED!", typeName)
        else:
            rearranged = True

        return definitions, rearranged

    def recursive_dep_check(self, typeDefMap, waitingStructs, key):
        if key in waitingStructs.keys():
            return True
        elif key in typeDefMap.keys():
            print("   ## Recursing", key, "->", newKey)
            newKey = typeDefMap[key]
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
                print("    !! FORWARD DECLARATION - STRUCT", typeName)
                definitions += "struct "+typeName+";\n"
                forward_declared.append(typeName)
            elif line.startswith("union"):
                # forward declaration
                typeName = line.strip().strip(";").rsplit(maxsplit=1)[1];
                print("    !! FORWARD DECLARATION - UNION", typeName)
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
                       
                        print("EVALUTING [%s] as Placeholder!" % typeName)
                        print("  ==", argTypeRaw)
                        print("  == ", (self.recursive_dep_check(typeDefMap, waitingStructs, typeName)))
                        print("  ==", (typeName not in rejectedPlaceholders))
                        if self.recursive_dep_check(typeDefMap, waitingStructs, typeName) and typeName not in rejectedPlaceholders:
                            if "union" in struct_or_union:
                                potentialPlaceholders.add("union "+typeName)
                            else:
                                potentialPlaceholders.add(typeName)
                        # if any of the waitingStructs use the needed placeholder without a pointer, reject this placeholder
                        if  "*" not in argTypeRaw:
                            print("removing ", argTypeLabel, "as placeholder. argTypeLabel", argTypeLabel)
                            print("    line: ", line)
                            if argTypeLabel in potentialPlaceholders:
                                potentialPlaceholders.remove(argTypeLabel)
                            rejectedPlaceholders.add(argTypeLabel)

        for placeholder in potentialPlaceholders:
            # create placeholder forward declaration
            if placeholder not in forward_declared:
                if "union" in placeholder:
                    print("Adding Placeholder ", placeholder)
                    definitions += placeholder+";\n"
                else:
                    print("Adding Placeholder Struct ", placeholder)
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
                print("Found const variable: ", line)
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
                print("removing assignment", assignLine)
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
    def remove_artifacts(self, lines):
        newlines = ""
        for line in lines.splitlines():
            if "<defs.h>" in line:
                continue
            # print(line)
            # print("---------")
            if "__cdecl" in line:
                # print("replacing line")
                line = line.replace("__cdecl", "")
                # print("newline", line)

            # handle :: classes
            line = line.replace("::", "__")

            # replace namings
            line = line.replace("int64", "long")
            line = line.replace("int32", "int")
            line = line.replace("int16", "short")
            line = line.replace("int8", "char")

            line = line.replace("bool", "_Bool")
            line = line.replace("_Bool", "_BoolDef") # TODO: dont use this dumbass workaround

            line = line.replace("_DWORD", "int")
            line = line.replace("_WORD", "short")
            line = line.replace("_BYTE", "char")
            line = line.replace("_UNKNOWN", "void")


            # strip __ precursors
            line = line.replace(" __long", " long")
            line = line.replace(" __int", " int")
            line = line.replace(" __short", " short")
            line = line.replace(" __char", " char")
            # line = line.replace(" __(", " (")
            # line = line.replace("*__", "*")



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

        print("GLOBAL DATA LINES : "+"\n".join(global_dataLines_)+"\n")
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
            print("Original:", line)
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

        print(f"fn_list : {fn_list}")
        for i in fn_list:
            print(f"->{i}")
            j=stubs_per_func[i]
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
                                  'nm_names':list(n)}
            v=sorted(ext_varprotos[f])
            #for k in v:
            #    for s in symvar_to_proto[k]:
            #        p.add(s)
            #        global_proto_var[k]=prot[k]
            
            resolved_var_syms[f] = {k:global_proto_var[k] for k in v }

        return resolved_fn_syms, resolved_var_syms, nm_to_decomp

    def get_stubs(self, lines, stubs, funcs, decomp_re, global_decomp, fn_symbols, data_symbols, translate_dict):
        # stubs, funcHeaders, h, s, f, d, g = cleaner.get_stubs(decomp_code,stubs,funcHeaders,detours_re,decomp_decls)
        instubs = False
        isFunc = False
        lstubs = {'prototypes':list(),'symbols':list(),'external':list(),'nm_names':list()}
        lfuncs = {'prototypes':list(),'symbols':list(),'external':list(),'nm_names':list()}
        global_fns = []

        
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
                nm_sym_name=sym_name
                ext_var=False
                if sym_name in data_symbols:
                    print("Found a data symbol!".format(sym_name))
                    ext_var=True
                elif sym_name not in fn_symbols:
                    print("Function declaration symbol name '{}' doesn't exist in symbol list!".format(sym_name))
                    print("line => {}".format(line))
                    print("Checking to see if it's an inlined alias, which is usually <fn>_\d+")
                    new_sym=re.sub(r'^(\w+)(_\d+)$',r'\1',sym_name)
                    alt_sym="_"+sym_name
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
                        nm_sym_name=alt_sym
                    else:
                        print("Error: can't resolve symbol '{}'".format(sym_name))
                        print("Skipping line")
                        continue
                        
                lstubs['symbols'].append(sym_name)
                lstubs['prototypes'].append(line)
                lstubs['nm_names'].append(nm_sym_name)
                decomp=decomp_re.search(sym_name)
                print("decomp_re : "+str(decomp_re))
                if decomp:
                    print("FOUND DECOMPILED FUNCTION  ' {}' : {}".format(decomp.group(0),line))
                    lstubs['external'].append(False)
                else:
                    lstubs['external'].append(True)
                    
                if line not in stubs['prototypes'] and not decomp:
                    stubs['symbols'].append(sym_name)
                    stubs['prototypes'].append(line)
                    stubs['external'].append(True)
                    stubs['nm_names'].append(nm_sym_name)
                elif line not in stubs['prototypes'] and decomp and line not in global_decomp:
                    print(f"global function => {line}")
                    print(f"global decomp => {global_decomp}")
                    print(f"stubs[prototypes] => {stubs['prototypes']}")
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
                if line not in funcs['prototypes']:
                    funcs['prototypes'].append(line)
                    funcs['symbols'].append(sym_name)
                    funcs['external'].append(False)
                    funcs['nm_names'].append(nm_sym_name)
                else:
                    continue

        #sections=(lines_[stub_idxs[0]]:stub_idxs[1]], lines_[stub_idxs[1]]:stub_idxs[-1]] )
        #stubs, funcHeaders, header_decls, s, f = cleaner.get_stubs(decomp_code,stubs,funcHeaders,header_decls)
        print("[COMPLETED] get_stubs",flush=True)
                                         # s
        return stubs, funcs, fulldecomp, lstubs, lfuncs, fn_start,global_fns,translate_dict

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
    def make_pcgc_stubs(self, stublines, funcs):
        stubMap = {}
        nonCGCList = []

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

            # if "cgc_" not in label:
            #     print("----- WARN: Non-CGC stub found!! ------")
            #     print(label)
            #     nonCGCList.append(label)
            #     continue

            print("    - RET [%s] LABEL [%s] ARGTYPES[%s]" % (ret_type, label, argTypes))

            stubArgs = ", ".join(argTypes)
            stubLine = "typedef " + ret_type + " (*p" + label + ")("+stubArgs+");\n"
            stubNull = "p"+label+" "+label+" = NULL;\n"
            stubMap[stub] = stubLine + stubNull

        return stubMap, nonCGCList

    def replace_stubs(self, output, stubMap):
        for stub, replacement in stubMap.items():
            output = output.replace(stub, replacement)
        return output


    def replace_data_defines_list(self, output, dataMap, removeList):
        for data, replacement in dataMap.items():
            print("   ---> Replacing [[%s]] with [[%s]]" %(data, replacement))
            for i in range(0,len(output)):
                output[i] = output[i].replace(data, replacement)
        for target in removeList:
            for i in range(0,len(output)):
                output[i] = output[i].replace(target, "")
        return output


       
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


    def generate_wrapper(self, target_list, funcs, stubMap, dataMap, detour_prefix, translation_dict):
        rev_trans={v:k for k,v in translation_dict.items()}
        mainStub = "void main()\n" + \
               "{\n"
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
            mainStub += "\t%s(\n" % detour_target
            print("Detour target: {}:{} => {} ".format(ltarget,trans_targ,detour_target))

            args = []
            targetHeader = ""
            targetRetType = "void"
            call_me[target]="{}".format(target)

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
                                print("DEBUG: arg = {}".format(arg))
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
            print("Replacing : {} with {} in '{}'".format(ltarget,detour_target,targetHeader))
            targetHeader = targetHeader.replace(ltarget,detour_target)

            wrapperStub += targetHeader.split("(", maxsplit=1)[0] #remove arguments
            wrapperStub += "(\n"


            print("dataMap", dataMap)
            # arguments to wrapper function

            for s in stubMap[target].keys():
                s_name=self.get_stub_name(s)
                s_name=translation_dict.get(s_name,s_name)
                mainStub +=  "\t\tNULL,\n" 
                wrapperStub += "\tvoid*"
                if s in self.weakFuncs:
                    wrapperStub += "*"
                wrapperStub += " my%s,\n" % s_name
                if ":" not in call_me[target]:
                    call_me[target]+=":"
                else:
                    call_me[target]+=","
                call_me[target]+=s_name
                print(s)
                print("  - STUBNAME: ", self.get_stub_name(s),s_name)
        
            # note from pdr: looks like when data declarations are included, the 
            # function prototype and funcstubs order of symbol definitions 
            # are not consistent
            for d in dataMap[target].keys():
                print("data", d)
                mainStub +=  "\t\tNULL,\n"
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
                argType = argTuple[0]
                argName = argTuple[1]
                if "double" in argType or "float" in argType or "int" in argType:
                    mainStub += "\t\t(%s) 0,\n"  % argType
                else:
                    mainStub += "\t\t(%s) NULL,\n"  % argType
                wrapperStub += "\t%s %s,\n" % (argType, argName)

            if stubMap or args: # list not empty
                mainStub = mainStub[:-2]  #strip ,\n
                wrapperStub = wrapperStub[:-2]  #strip ,\n

            mainStub += "\n\t);\n"
            # pdr : need to move this outside of FOR loop
            #mainStub += "}\n"

            wrapperStub += "\n)\n{\n"
    
            # create ret variable if needed
            if targetRetType != "void":
                wrapperStub += "\n\t%s retValue;\n\n" % targetRetType
    
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
                dname=translation_dict.get(name,name)
                wrapperStub += "\t%s = (p%s) (" % (name, name)
                if s in self.weakFuncs:
                    wrapperStub += "*"
                wrapperStub += "my%s);\n" % (dname)
    
            numStubs = len(stubMap[target])
            numFuncArgs = len(args)
    
            wrapperStub += "\n\t__prd_init();\n"
    
    
            wrapperStub += "\t"
    
            if targetRetType != "void":
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
            if targetRetType != "void":
                wrapperStub += " retValue"
            wrapperStub += ";\n}\n\n"


        # print("---------- MAIN STUB -------------")
        # print(mainStub)
        # print("---------- wrapperStub -------------")
        # print(wrapperStub)

        # pdr : move this to outside of FOR loop
        mainStub += "}\n"

        return  wrapperStub + "\n\n" + mainStub, call_me



class Formatter:

    def __init__(self):
        pass

class GenprogDecomp:

    def __init__(self, target_list_path, scriptpath, ouput_directory,entryfn_prefix):
        self.target_list_path = target_list_path
        self.scriptpath = scriptpath
        self.ouput_directory = ouput_directory
        self.detour_entry_fn_prefix=entryfn_prefix

    def get_symbols(self,binary_path):
        cmd=["/usr/bin/nm",binary_path]
        symproc=subprocess.Popen(" ".join(cmd),stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=True)
        #ret=symproc.poll()
        #if ret == None:
        #    ret=symproc.poll()
        #    print("Error running '{}' {} ".format(" ".join(cmd),ret))
        #    return None
        sout,serr = symproc.communicate()
        output=sout.decode('ISO-8859-1')
        lines=output.split('\n')
        print(lines[0])
        symbol_dict = dict()
        for x in lines:
            if len(x)<1:
                print(x)
                continue
            symadd=x[0:8]
            symtype=x[9:10]
            symname=x[11:len(x)]
            ltype=symbol_dict.get(symtype,None)
            if not ltype:
                symbol_dict[symtype]=list()
            symbol_dict[symtype].append({'name':symname,'address':symadd,'type':symtype})
        return symbol_dict






    def run(self):
        idaw = IDAWrapper(self.scriptpath)
        cleaner = CodeCleaner()
        functions = []
        success = []
        failure = []
        with open(self.target_list_path, "r") as targetFile:
            for line in targetFile:
                if len(line)<=0:
                    continue
                else:
                    print(line)
                finalOutput = ""
                dataMap=dict()

                target, path, funcs = line.rstrip().split(",")
                target = target.strip()
                path = path.strip()
                funcList = funcs.split(":")
                detour_funcs= [ f.strip() for f in funcList ]
                detours_regex="|".join(detour_funcs)
                while detours_regex[-1]=='|':
                    detours_regex=detours_regex[0:-2]
                detours_re=re.compile(r"\b("+detours_regex+r")\b")
                mainFunc = funcList[0].strip()

                print("="*100)
                print("Decompile and Recompiling: %s in target %s" %(str(detour_funcs), target))
                print("="*100)

                print("    --- Getting typedef mappings...")
                structDump = idaw.get_typedef_mappings(path)
                # print(structDump)
                typedefLines = cleaner.remove_artifacts(structDump)
                typedefLines = cleaner.cleanup_typedefs(typedefLines)

                finalOutput += typedefLines

                print("    --- Decompiling target functions...")
                symbols_lut = self.get_symbols(path)
                data_symbols = [ x['name'] for s in ['d','D','b','B'] for x in symbols_lut[s] ]
                fn_symbols = [ x['name'] for s in ['t','T','U'] for x in symbols_lut[s] ]
                print("DATA SYMBOLS: {}".format(" ".join(data_symbols)))

                # void __prd_init() and void __prd_exit() function definitions
                finalOutput += cleaner.generate_det_placeholders()

                fulldecomp_code=""
                stubs={'prototypes':list(),'symbols':list(),'external':list(),'nm_names':list()}
                funcHeaders={'prototypes':list(),'symbols':list(),'external':list(),'nm_names':list()}
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
                for idx,func in enumerate(funcList):
                    print(f"Processing Function: {func}")
                    #fname="/tmp/decomp_raw.c."+str(idx)
                    #if os.path.exists(fname):
                    #    decompFH=open(fname,"r")
                    #    decomp_code=decompFH.read()
                    #    decompFH.close()
                    #else:    
                    #    decomp_code = idaw.decompile_func(path, func)
                    #    decompFH=open(fname,"w")
                    #    decompFH.write(decomp_code)
                    #    decompFH.close()
                    decomp_code = idaw.decompile_func(path, func)
                    decomp_code = re.sub(r"\bmain\b","patchmain",decomp_code)
                    if func not in fn_symbols:
                        print(f"{func} not in {fn_symbols}")
                        print("invalid function symbol, skipping...")
                        failure.append((target, path, func))
                        continue

                    #decompFH.write(decomp_code)
                    stubs_per_func[detour_funcs[idx]]=list()
                    funcHeaders_per_func[detour_funcs[idx]]=dict()
                    if len(decomp_code) <= 0:
                        print("decompilation error, skipping...")
                        failure.append((target, path, func))
                        continue

                    decomp_code = cleaner.remove_artifacts(decomp_code)
                    print(decomp_code)

                    print("    --- Creating stubs...")
                    #      dataMap [per fun] ; dataMap_ [global]
                    #return dataMap, removeList, dataMap_, dataLines_
                    dataMap, dataRemoveList, d, data_decls = cleaner.get_data_declarations(decomp_code,data_symbols,dataMap, data_decls)
                    # d = {'prototypes':dict(),'sym2proto':dict(),'ext_vars':set(),'local_vars':set()} 
                    #data_syms={'ext_var':ext_var_syms,'local_var':local_var_syms}
                    dataMap_per_func[detour_funcs[idx]]=d
                    # stubs are the Function declaration section content [external and local function prototypes]
                    # funcHeaders are the local function definitions
                    stubs, funcHeaders, h, s, f, d, g, translate_dict = cleaner.get_stubs(decomp_code,stubs,funcHeaders,detours_re,decomp_decls,fn_symbols,data_symbols,translate_dict)
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
                    decomp_decls+=g
                    stubs_per_func[detour_funcs[idx]]=s
                    funcHeaders_per_func[detour_funcs[idx]]=f['prototypes']
                    #fulldecomp_code += decomp_code

                #decompFH.close()
                func_decls=stubs['prototypes']
                #data_decls=[ f for f in funcHeaders if (";" in f and f not in stubs) ] 
                #data_decls=[ f for f in funcHeaders if (";" in f and f not in stubs) ] 
                decomp_defs=[]
                for i in decomp_per_func.keys():
                    decomp_defs.extend(decomp_per_func[i])
                # print("---- stubs ----")
                # for s in stubs:
                #     print(s)
                # print("---- funcs ----")
                # for f in funcHeaders:
                #     print(f)

                # let's uniquify the header lines by the set datatype
                print("\nFUNC_HEADERS:\n{}".format(" -- "+"\n -- ".join(funcHeaders['prototypes'])))
                print("\nDATA_DECLS:\n{}".format(" -- "+"\n -- ".join(data_decls)))
                print("\nFUNC_DECLS:\n{}".format(" -- "+"\n -- ".join(func_decls)))
                print("\nDECOMP_DECLS:\n{}".format(" -- "+"\n -- ".join(decomp_decls)))
                print("\nDECOMP_DEFS:\n{}".format(" -- "+"\n -- ".join(decomp_defs)))
                # replacing data declarations with the defines
                data_decls = cleaner.replace_data_defines_list(data_decls, dataMap, dataRemoveList)

                full_=header_decls[0:6]+["\n","//"+"-"*68,"// Function Declarations","\n"]
                full_+=func_decls+["\n"]
                full_+=["\n","//"+'-'*68,"// Decompiled Variables"]+data_decls+["\n"]
                full_+=["\n","//"+'-'*68,"// Decompiled Function Declarations"]+decomp_decls+["\n"]
                full_+=["\n","//"+'-'*68,"// Decompiled Function Definitions"]+decomp_defs+["\n"]
                #finalOutput+="\n\n"+"\n".join(header_decls[0:6]+func_decls+data_decls+decomp_decls)+"\n\n"
                finalOutput+="\n\n"+"\n".join(full_)+"\n\n"
                # this following line replaces content in parts of the code we don't want
                #finalOutput = cleaner.replace_data_defines(finalOutput, dataMap, dataRemoveList)


                stubMap_=dict()
                nonCGCList_=dict()
                updated_stubs,updated_dataMap,nm2decomp_syms=cleaner.resolve_dependencies(stubs_per_func,dataMap_per_func)

                stubMap, nonCGCList= cleaner.make_pcgc_stubs(stubs, funcHeaders['prototypes'])
                for f in detour_funcs:
                    #stubMap_[f], nonCGCList_[f] = cleaner.make_pcgc_stubs(stubs_per_func[f],funcHeaders_per_func[f])
                    stubMap_[f], nonCGCList_[f] = cleaner.make_pcgc_stubs(updated_stubs[f],funcHeaders['prototypes'])
                # finalOutput = cleaner.remove_nonCGC_calls(finalOutput, nonCGCList)
                finalOutput = cleaner.replace_stubs(finalOutput, stubMap)
                # pdr update - let's not rename the functions
                # finalOutput = cleaner.rename_target(finalOutput, mainFunc)
                    

                print("    --- Additional cleaning")                
                finalOutput = cleaner.handle_const_assigns(finalOutput, funcHeaders)

                print("    --- Generating wrappers...")
                header = "// Auto-generated code for recompilation of target [%s]\n\n" % target
                finalOutput = header + finalOutput
                finalOutput = "#include \"defs.h\"\n" + finalOutput
                finalOutput = "#include <stddef.h>\n\n" + finalOutput

                # we just don't want mainFunc, we want all detoured functions
                #footer = cleaner.generate_wrapper(mainFunc, funcHeaders, stubMap, dataMap, self.detour_entry_fn_prefix)
                #footer,transl_dict = cleaner.generate_wrapper(detour_funcs, funcHeaders, stubMap, dataMap, self.detour_entry_fn_prefix)
                footer,detfn_defs = cleaner.generate_wrapper(detour_funcs, funcHeaders_per_func, stubMap_, updated_dataMap, self.detour_entry_fn_prefix,translate_dict)

                finalOutput += footer

                print("Recompilation Complete!")

                outdir = os.path.join(self.ouput_directory, target)
                if not os.path.exists(outdir):
                    os.makedirs(outdir)

                print("\nWriting to ", outdir)

                outpath = os.path.join(self.ouput_directory, target, target+"_recomp.c")
                with open(outpath, "w") as outFile:
                    outFile.write(finalOutput)
                outFile.close()
                success.append((target, path, funcList))

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
                funcStubline = re.sub('\[\d*\]',""," ".join(funcStubs))
                detours = []
                for i in detfn_defs.keys():
                    di=i
                    define=di
                    if self.detour_entry_fn_prefix:
                        di="{}{}".format(self.detour_entry_fn_prefix,i)
                        define="{}:{}".format(di,i)
                    elif i=="main":
                        di="patchmain"
                        define="{}:{}".format(di,i)

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
                "FUNCSTUB_LIST": detfn_defs
                }
                # pdr: should really put this in in a separate configuration parsing 
                #      and generation script/program
                makefile_target_info = "# Auto-generated Makefile include file\n"  + \
                              "BIN := " + target + "\n" + \
                              "DETOUR_BIN ?= $(BIN).trampoline.bin\n" + \
                              "MYSRC ?= " + target+"_recomp.c" + "\n" + \
                              "MYREP ?= " + "repair.c" + "\n" + \
                              "DETOUR_PREFIX := " + self.detour_entry_fn_prefix + "\n" + \
                              "DETOUR_DEFS := " + funcStubline + "\n" + \
                              "DETOUR_CALLS := $(patsubst %, --external-funcs $(DETOUR_PREFIX)%, $(DETOUR_DEFS))\n" + \
                              "DETOURS := " + " ".join(detours) + "\n" + \
                              "FUNCINSERT_PARAMS := $(DETOURS) $(DETOUR_CALLS) --debug \n" 
                              #"FUNCINSERT_PARAMS := --detour-prefix $(DETOUR_PREFIX) $(DETOURS)\n" 

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
        targetFile.close()

        print(" ALL TARGETS COMPLETE")
        print(" --- %d binaries successesful recompiled" % len(success))
        for s in success:
            print("     - ", s)
        print(" --- %d binaries failed" % len(failure))
        for f in failure:
            print("     - ", f)
        print("="*100)




def main():
    if not os.path.isfile(IDA_PATH):
        print("ERROR: Environmental variable IDA_BASE_PATH is not set or '"+IDA_DEFAULT_PATH+"' does not exist")
        import sys
        sys.exit(-1)
    parser = argparse.ArgumentParser(description='')
    parser.add_argument('--detour-prefix',dest='detfn_prefix',action='store',default="det_",
                        help='Detour prefix to append to detour entry function')
    parser.add_argument('target_list',
                        help='path to the list of target binaries + paths')
    parser.add_argument('ouput_directory',
                        help='path to output directory')
    parser.add_argument('--scriptpath', default="get_ida_details.py",
                    help='path to idascript')

    args, unknownargs = parser.parse_known_args()
    gpd = GenprogDecomp(args.target_list, args.scriptpath, args.ouput_directory,args.detfn_prefix)
    gpd.run()

main()


# idascript line
# htay@htay-OptiPlex-7070:~/genprog_decomp/tests$ ~/ida-7.1/idat -Ohexrays:-nosave:ascii_test:cgc_WalkTree -A ASCII_Content_Server
