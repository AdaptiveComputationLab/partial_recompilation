import ida_pro
import ida_auto
import ida_funcs
import ida_hexrays
import ida_segment
import idautils
import ida_typeinf
import idc
import time

START = "============================== START =============================="
END = "============================== END =============================="

def get_typedefs():
    idati = ida_typeinf.get_idati()

    decls=""

    for ordinal in range(0, ida_typeinf.get_ordinal_qty(idati)):
        decls+="%d," % ordinal
        # ti = ida_typeinf.tinfo_t()
        # if ti.get_numbered_type(idati, ordinal):
        #     print ordinal, ti
        #     test = ti.serialize()
        #     print type(test)
    if decls.endswith(","):
        decls = decls[:-1]
    print("decls:", decls)
    out = idc.print_decls(decls, 4)
    print(out)
                        # ti.print()
    return

def main():
    print(START)
    # print("Idc args: " + str(idc.ARGV))
    get_typedefs()
    print(END)
    return

ida_auto.auto_wait()
main()
ida_pro.qexit(0)