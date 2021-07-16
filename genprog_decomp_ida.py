import os
import subprocess
import IPython
import argparse
import tempfile
import re
import shutil
import time

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
    def decompile(self, binary_path, func_list):
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
        with tempfile.NamedTemporaryFile(mode="r", dir="/tmp", prefix="genprog-ida-",delete=True) as tmpFile:
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

    def getTypeAndLabel(self, header):
        if ")" in header and "((aligned(" not in header and "()" not in header:
            array = header.rsplit(")", maxsplit=1)
            hType = array[0].strip()+")"

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
                            print("      Associating %s with %s [%s]" % (typedefLine, line, origName))
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

    def get_data_declarations(self, lines):
        inData = False
        dataLines = []
        dataMap = {}
        removeList = []
        for line in lines.splitlines():
            if IDA_DATA_START in line:
                inData = True
                continue
            elif IDA_SECTION_END in line:
                inData = False
                continue

            if inData and len(line.strip()) > 0:
                dataLines.append(line)

        print("DATA LINES")
        line = ""
        for dataLine in dataLines:
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

            dataType, dataName = self.getTypeAndLabel(header)
            array_size=len(re.findall("\[\d*\]",dataName))
            print("Array Size:", array_size)
            defLine=""
            if array_size>=2:
                print("// --- WARNING! Two-dimensional array objects are not yet supported")
                defLine += "%s *(p%s);\n" %(dataType, dataName)
                dataName = dataName.split("[")[0] # handle arrays
                defLine += "#define %s (*p%s)\n" % (dataName, dataName)
                print(" // --- END OF WARNING!\n")
            elif array_size==1 and "*" not in dataType:
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
            dataMap[line] = defLine
            line = ""

        print("REMOVE LIST", removeList)
        return dataMap, removeList


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

    def get_stubs(self, lines):
        instubs = False
        isFunc = False
        stubs = []
        funcs = []
        for line in lines.splitlines():
            if IDA_STUB_START in line:
                instubs = True
                continue
            elif IDA_SECTION_END in line:
                instubs = False
                isFunc = True
                continue

            line = line.strip()
            if instubs and len(line.strip()) > 0:
                stubs.append(line)
            elif isFunc and len(line.strip()) > 0 and not line.startswith("//"): #is part of function declarations
                funcs.append(line)
                isFunc = False

        return stubs, funcs

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

        for stub in stublines:
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
        placeholders = "void __prd_init() {\n}\n"
        placeholders += "void __prd_exit() {\n}\n"
        return placeholders


    def generate_wrapper(self, target, funcs, stubMap, dataMap):
        mainStub = "void main()\n" + \
               "{\n\t%s(\n" % target
        wrapperStub = ""

        args = []
        targetHeader = ""
        targetRetType = "void"

        for f in funcs:
            print(target, f)
            if target in f:
                # print(f)
                targetHeader = f
                array = f.split("(", maxsplit=1)
                targetRetType, targetName = self.getTypeAndLabel(array[0])
                if len(array)<2:
                    break #no arguments
                else:
                argLine = array[1].strip(";").strip(")")
                # print(f, argLine)
                if len(argLine.strip()) <= 0:
                    break #no arguments
                argArray = argLine.split(",")
                for arg in argArray:
                    arg = arg.strip()
                    argTuple = self.getTypeAndLabel(arg)
                    args.append(argTuple)
                break
                    

        if target == "main":
            target = "patch" + target
            targetHeader = targetHeader.replace("main", "patchmain")

        wrapperStub += targetHeader.split("(", maxsplit=1)[0] #remove arguments
        wrapperStub += "(\n"


        print("dataMap", dataMap)
        # arguments to wrapper function

        for s in stubMap.keys():
            mainStub +=  "\t\tNULL,\n" 
            wrapperStub += "\tvoid*"
            if s in self.weakFuncs:
                wrapperStub += "*"
            wrapperStub += " my%s,\n" % self.get_stub_name(s)
            print(s)
            print("  - STUBNAME: ", self.get_stub_name(s))
        
        # note from pdr: looks like when data declarations are included, the 
        # function prototype and funcstubs order of symbol definitions 
        # are not consistent
        for d in dataMap.keys():
            print("data", d)
            mainStub +=  "\t\tNULL,\n"
            dataDef = d.split(";")[0]
            dataDef = dataDef.split("=")[0].strip()
            dataType, dataName = self.getTypeAndLabel(dataDef)
            array_size=len(re.findall("\[\d*\]",dataName))
            if array_size>=2:
                print("SORRY: two-dimensional array objects just aren't working right now")
                print(" ==> "+dataType+" "+dataName)
                wrapperStub += "// --- WARNING! Two-dimensional array objects are not yet supported"
                wrapperStub += "\tvoid* my%s,\n" % dataName
            elif array_size==1 and "*" not in dataType:
                dataNamex = dataName.split("[")[0] # handle arrays
                wrapperStub += "\tvoid* my%s,\n" % dataNamex
            else:
                wrapperStub += "\tvoid* my%s,\n" % dataName
            print("   - DATA DECL: ", dataName)

        for argTuple in args:
            argType = argTuple[0]
            argName = argTuple[1]
            mainStub += "\t\t(%s) NULL,\n"  % argType
            wrapperStub += "\t%s %s,\n" % (argType, argName)

        if stubMap or args: # list not empty
            mainStub = mainStub[:-2]  #strip ,\n
            wrapperStub = wrapperStub[:-2]  #strip ,\n

        mainStub += "\n\t);\n"
        mainStub += "}\n"

        wrapperStub += "\n)\n{\n"

        # create ret variable if needed
        if targetRetType != "void":
            wrapperStub += "\n\t%s retValue;\n\n" % targetRetType

        # body
        for d in dataMap.keys():
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
            elif array_size==1 and "*" not in dataType:
                dataNamex = dataName.split("[")[0] # handle arrays
                wrapperStub += "\tp%s = (%s*) my%s;\n" % (dataNamex, dataType, dataNamex)
            else:
                wrapperStub += "\tp%s = (%s*) my%s;\n" % (dataName, dataType, dataName)

        for s in stubMap.keys():
            name = self.get_stub_name(s)
            wrapperStub += "\t%s = (p%s) (" % (name, name)
            if s in self.weakFuncs:
                wrapperStub += "*"
            wrapperStub += "my%s);\n" % (name)

        numStubs = len(stubMap)
        numFuncArgs = len(args)

        wrapperStub += "\n\t__prd_init();\n"


        wrapperStub += "\t"

        if targetRetType != "void":
            wrapperStub += "retValue = "

        # call target:

        wrapperStub += "my%s(\n" % target

        for argTuple in args:
            argName = argTuple[1]
            wrapperStub += "\t\t%s,\n" % (argName)

        if args: # list not empty
            wrapperStub = wrapperStub[:-2]  #strip ,\n

        wrapperStub += "\n\t);\n"

        wrapperStub += "\n\t__prd_exit();\n"

        # asm
        wrapperStub += "\n\t /* ASM STACK HERE */\n"

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
        wrapperStub += ";\n}\n"


        # print("---------- MAIN STUB -------------")
        # print(mainStub)
        # print("---------- wrapperStub -------------")
        # print(wrapperStub)

        return  wrapperStub + "\n\n" + mainStub


class Formatter:

    def __init__(self):
        pass

class GenprogDecomp:

    def __init__(self, target_list_path, scriptpath, ouput_directory):
        self.target_list_path = target_list_path
        self.scriptpath = scriptpath
        self.ouput_directory = ouput_directory

    def run(self):
        idaw = IDAWrapper(self.scriptpath)
        cleaner = CodeCleaner()
        functions = []
        success = []
        failure = []
        with open(self.target_list_path, "r") as targetFile:
            for line in targetFile:
                finalOutput = ""

                target, path, funcs = line.split(",")
                target = target.strip()
                path = path.strip()
                funcList = funcs.split(":")
                mainFunc = funcList[0].strip()

                print("="*100)
                print("Decompile and Recompiling: %s in target %s" %(mainFunc, target))
                print("="*100)

                print("    --- Getting typedef mappings...")
                structDump = idaw.get_typedef_mappings(path)
                # print(structDump)
                typedefLines = cleaner.remove_artifacts(structDump)
                typedefLines = cleaner.cleanup_typedefs(typedefLines)

                finalOutput += typedefLines

                print("    --- Decompiling target functions...")
                decomp_code = idaw.decompile(path, funcList)
                if len(decomp_code) <= 0:
                    print("decompilation error, skipping...")
                    failure.append((target, path, funcList))
                    continue

                decomp_code = cleaner.remove_artifacts(decomp_code)
                finalOutput += cleaner.generate_det_placeholders()
                finalOutput += decomp_code

                print(decomp_code)

                print("    --- Creating stubs...")
                dataMap, dataRemoveList = cleaner.get_data_declarations(decomp_code)
                stubs, funcHeaders = cleaner.get_stubs(decomp_code)
                # print("---- stubs ----")
                # for s in stubs:
                #     print(s)
                # print("---- funcs ----")
                # for f in funcHeaders:
                #     print(f)
                finalOutput = cleaner.replace_data_defines(finalOutput, dataMap, dataRemoveList)


                stubMap, nonCGCList = cleaner.make_pcgc_stubs(stubs, funcHeaders)
                # finalOutput = cleaner.remove_nonCGC_calls(finalOutput, nonCGCList)
                finalOutput = cleaner.replace_stubs(finalOutput, stubMap)
                finalOutput = cleaner.rename_target(finalOutput, mainFunc)

                print("    --- Additional cleaning")                
                finalOutput = cleaner.handle_const_assigns(finalOutput, funcHeaders)

                print("    --- Generating wrappers...")
                header = "// Auto-generated code for recompilation of target [%s]\n\n" % target
                finalOutput = header + finalOutput
                finalOutput = "#include \"defs.h\"\n" + finalOutput
                finalOutput = "#include <stddef.h>\n\n" + finalOutput

                footer = cleaner.generate_wrapper(mainFunc, funcHeaders, stubMap, dataMap)

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

                funcStubline = ""
                for stubLine in stubMap.keys():
                    stubName = cleaner.get_stub_name(stubLine)
                    funcStubline += stubName +","

                for dataStub in dataMap.values():
                    # IPython.embed()
                    dataDef = dataStub.split("\n")[1]
                    dataName = dataDef[8:].split(maxsplit=1)[0]
                    funcStubline += dataName +","
                funcStubline = funcStubline.strip(",")

                funcStubline = mainFunc+":"+funcStubline
                print(funcStubline)
                outpath = os.path.join(self.ouput_directory, target, target+"_funcstubs")
                with open(outpath, "w") as outFile:
                    outFile.write(funcStubline)
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
    parser.add_argument('target_list',
                        help='path to the list of target binaries + paths')
    parser.add_argument('ouput_directory',
                        help='path to output directory')
    parser.add_argument('--scriptpath', default="get_ida_details.py",
                    help='path to idascript')

    args, unknownargs = parser.parse_known_args()
    gpd = GenprogDecomp(args.target_list, args.scriptpath, args.ouput_directory)
    gpd.run()

main()


# idascript line
# htay@htay-OptiPlex-7070:~/genprog_decomp/tests$ ~/ida-7.1/idat -Ohexrays:-nosave:ascii_test:cgc_WalkTree -A ASCII_Content_Server
