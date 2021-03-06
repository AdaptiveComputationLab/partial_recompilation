import argparse
import os
import subprocess
import time

CREATE_ASM = "create_asm.py"
ASM_START_MARKER = "In-line assembly for compilation:"
ASM_STUB_MARKER = "/* ASM STACK HERE */"

class ASM_Fitter():
    def __init__(self, target_list_path, target_directory):
        self.target_list_path = target_list_path
        self.target_directory = target_directory


    def run(self):
        with open(self.target_list_path, "r") as targetFile:
            for line in targetFile:
                target, path, funcs = line.split(",")
                target = target.strip()
                path = path.strip()
                funcList = funcs.split(":")
                mainFunc = funcList[0].strip()

                targetPath = os.path.join(self.target_directory, target, target+"_recomp.c")
                targetBaseDir = os.path.join(self.target_directory, target)
                targetObjDumpPath = os.path.join(self.target_directory, target, "objdump.txt")
                outputRunPath = os.path.join(self.target_directory, target, "run")
                createASMPath = os.path.join(self.target_directory, CREATE_ASM)
                funcArgs = ",".join(funcList[1:])
                funcArgs = mainFunc+":"+funcArgs
                funcArgs = "\""+funcArgs.strip(":")+"\""
                print("Fitting", target)
                # print(createASMPath)
                # print(funcArgs)

                if os.path.exists(targetPath):
                    subprocess.run(["gcc", targetPath, "-m32", "-w", "-o", outputRunPath])
                    command = ["objdump", "-d", outputRunPath]
                    # print("Running", command)
                    # subprocess.run(command)
                    p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    out, err = p.communicate()
                    with open(targetObjDumpPath, "wb") as dumpFile:
                        dumpFile.write(out)
                    dumpFile.close()
                    # print(out)
                    # print(err)
                    os.chdir(targetBaseDir)
                    # print("Running:")
                    command = [createASMPath, "--objdump-log", targetObjDumpPath, "--debug", "--func", funcArgs, ">", "tmp"]
                    commandLine = " ".join(command)
                    # print(" ".join(command))
                    # subprocess.call(command)
                    # p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    # out, err = p.communicate()
                    # print(out)
                    os.system(commandLine)

                    with open("tmp", "r") as tmpFile:
                        lines = tmpFile.read()
                    tmpFile.close()

                    inASM = False
                    asmCode = ""
                    for line in lines.splitlines():
                        if inASM:
                            asmCode += "\t"+ line + "\n"
                            if ");" in line:
                                inASM = False
                        if ASM_START_MARKER in line:
                            inASM = True
                    # print(asmCode)

                    with open(targetPath, "r") as targetFile:
                        lines = targetFile.read()
                    targetFile.close()

                    lines = lines.replace(ASM_STUB_MARKER, "\n"+asmCode)
                    # print(lines)

                    with open(targetPath, "w") as targetFile:
                        targetFile.write(lines)
                    targetFile.close()
                    print("   - Done")
                else:
                    print("   - %s does not exist" % targetPath)



def main():
    parser = argparse.ArgumentParser(description='')
    parser.add_argument('target_list',
                        help='path to the list of target binaries + func info')
    parser.add_argument('target_directory',
                        help='path to target directory')

    args, unknownargs = parser.parse_known_args()
    asmFitter = ASM_Fitter(args.target_list, args.target_directory)
    asmFitter.run()

main()