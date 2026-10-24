################################################################################
#
#   Copyright (C) 2014  Cisco Systems, Inc./SourceFire, Inc.
#
#   Author: Angel M. Villegas (anvilleg [at] sourcefire [dot] com)
#           Frederick W Sell (frsell [at] cisco [dot] com)
#
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 2 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License along
#   with this program; if not, write to the Free Software Foundation, Inc.,
#   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
#   Last Modified: July 29, 2022
#   Description:
#       IDA Python script that locates all references to DllFunctionCall,
#       creates structures, applies structures to the argument provided to
#       DllFunctionCall, labels structures based on the API to be loaded,
#       defines and renames functions used to dynamically load API, and
#       registers the function dynamically loaded. Upon completion, a list of
#       all dynamically loaded API is printed out
#
#
#   VB DllFunctionCall(DllFunctionCallStruct * dllInfo);
#   ============================================================================
#   		typedef struct _DynamicHandles {
#   0x00
#   0x04        HANDLE hModule;
#   0x08        VOID * fnAddress
#   0x0C
#           } DynamicHandles;
#
#           typedef struct _DllFunctionCallStruct {
#   0x00        LPCSTR lpDllName;
#   0x04        LPTSTR lpExportName;
#   0x08
#   0x09
#               // 4 bytes means it is a LPTSTR *
#               // 2 bytes means it is a WORD (the export's numeric Ordinal)
#   0x0A        char addressAlignment;
#   0x0B
#   0x0C        DynamicHandles * sHandleData;
#   0x10
#           } DllFunctionCallStruct;
#
################################################################################

# Adapted from vb_DllFunctionCall.py (Cisco Talos, GPLv2+) for IDA 9.x / Python 3
# Locates references to DllFunctionCall (VB6), applies the structures,
# renames the wrappers, and displays the list of dynamically loaded APIs.

import re
import idaapi
import idautils
import idc
import ida_bytes
import ida_funcs
import ida_name
import ida_nalt
import ida_typeinf

DLL_STRUCT = 'DllFunctionCallStruct'
HANDLES_STRUCT = 'DynamicHandles'

# Base 32 bits (binaire VB6 x86) : les pointeurs font 4 octets.
TYPE_DECLS = """
struct DynamicHandles {
    unsigned int reserved;      // 0x00
    void *hModule;              // 0x04
    void *fnAddress;            // 0x08
};

struct DllFunctionCallStruct {
    char *lpDllName;            // 0x00
    char *lpExportName;         // 0x04
    unsigned __int16 ordinal;   // 0x08
    unsigned __int8 sizeOfExportName; // 0x0A
    unsigned __int8 pad;        // 0x0B
    struct DynamicHandles *ptrHandles; // 0x0C
};
"""

NAME_FLAGS = idc.SN_CHECK | ida_name.SN_FORCE


def safe(name):
    return re.sub(r'[^A-Za-z0-9_]', '_', name)


def get_tinfo(name):
    tif = ida_typeinf.tinfo_t()
    if tif.get_named_type(ida_typeinf.get_idati(), name):
        return tif
    return None


def ensure_types():
    t1, t2 = get_tinfo(HANDLES_STRUCT), get_tinfo(DLL_STRUCT)
    if t1 and t2:
        if t1.get_size() == 0xC and t2.get_size() == 0x10:
            return True
        print('\t[!] Types existants avec une taille inattendue '
              '(supprimez-les dans Local Types puis relancez)')
        return False
    print('\t[+] Création des structures...')
    errors = idc.parse_decls(TYPE_DECLS, idc.PT_SIL)
    if errors:
        print('\t[!] Erreur(s) de parsing des déclarations : {0}'.format(errors))
        return False
    return bool(get_tinfo(HANDLES_STRUCT) and get_tinfo(DLL_STRUCT))


def apply_struct(ea, name):
    tif = get_tinfo(name)
    ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, tif.get_size())
    return ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.TINFO_DEFINITE)


def read_cstr(ea):
    """Lit une chaîne C, la définit dans l'IDB et la renvoie en str."""
    if ea in (0, idc.BADADDR) or not ida_bytes.is_loaded(ea):
        return None
    raw = ida_bytes.get_strlit_contents(ea, -1, ida_nalt.STRTYPE_C)
    if not raw:
        return None
    ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, len(raw) + 1)
    ida_bytes.create_strlit(ea, 0, ida_nalt.STRTYPE_C)
    return raw.decode('ascii', errors='replace')


def prev_ea(ea):
    insn = idautils.DecodePreviousInstruction(ea)
    return insn.ea if insn else idc.BADADDR


def define_function(ea):
    # Attendu :
    #   mov eax, dword_ZZZZ / or eax, eax / jz loc_X / jmp eax
    # loc_X: push YYYY / mov eax, offset DllFunctionCall / call eax / jmp eax
    jmp_i = prev_ea(ea)
    jz_i = prev_ea(jmp_i) if jmp_i != idc.BADADDR else idc.BADADDR
    or_i = prev_ea(jz_i) if jz_i != idc.BADADDR else idc.BADADDR
    mov_i = prev_ea(or_i) if or_i != idc.BADADDR else idc.BADADDR
    if idc.BADADDR in (jmp_i, jz_i, or_i, mov_i):
        print('\t[!] Impossible de remonter jusqu\'au début de la fonction')
        return
    if (idc.print_insn_mnem(jmp_i) != 'jmp' or idc.print_insn_mnem(jz_i) != 'jz'
            or idc.print_insn_mnem(or_i) != 'or'
            or idc.print_insn_mnem(mov_i) != 'mov'):
        print('\t[!] Motif de fonction inattendu à 0x{0:x}'.format(mov_i))
    if not ida_funcs.add_func(mov_i):
        print('\t[!] Impossible de définir la fonction à 0x{0:x}'.format(mov_i))


def print_api(data):
    fmt = '{0:25} {1}'
    for dll in sorted(data):
        for fn in sorted(data[dll]):
            print(fmt.format(dll, fn))


def main():
    print('Starting...')
    if not ensure_types():
        return

    target = idc.get_name_ea_simple('DllFunctionCall')
    if target == idc.BADADDR:
        print('\t[!] DllFunctionCall introuvable (renommez-la d\'abord)')
        return

    dynamic_api = {}
    count = 0

    for xref in idautils.CodeRefsTo(target, 1):
        prev_i = prev_ea(xref)
        if prev_i == idc.BADADDR:
            continue
        struct_instr = prev_ea(prev_i)
        if struct_instr == idc.BADADDR:
            continue

        # L'instruction doit être : push offset struct
        if (idc.print_insn_mnem(struct_instr) != 'push'
                or idc.get_operand_type(struct_instr, 0) != idc.o_imm):
            continue

        idc.op_plain_offset(struct_instr, 0, 0)
        struct_ea = idc.get_operand_value(struct_instr, 0)

        apply_struct(struct_ea, DLL_STRUCT)
        dll_name = read_cstr(ida_bytes.get_dword(struct_ea))
        fn_name = read_cstr(ida_bytes.get_dword(struct_ea + 4))

        if not dll_name or not fn_name:
            print('\t[!] 0x{0:x} : export par ordinal ou chaîne illisible, ignoré'
                  .format(struct_ea))
            continue

        base = safe(fn_name)
        idc.set_name(struct_ea, 'struct_' + base, NAME_FLAGS)

        # Sous-structure (handles)
        sub_ea = ida_bytes.get_dword(struct_ea + 0xC)
        if sub_ea and ida_bytes.is_loaded(sub_ea):
            apply_struct(sub_ea, HANDLES_STRUCT)
            idc.set_name(sub_ea, 'subStruct_' + base, NAME_FLAGS)

        # Fonction wrapper
        if not idc.get_func_name(struct_instr):
            print('\t[+] Fonction non définie, création...')
            define_function(struct_instr)

        func = ida_funcs.get_func(struct_instr)
        if not func:
            print('\t[!] Pas de fonction à 0x{0:x}'.format(struct_instr))
        else:
            wrapper_name = base + '_wrapper'
            if not idc.set_name(func.start_ea, wrapper_name, NAME_FLAGS):
                print('\t[!] Échec du renommage de la fonction à 0x{0:x}'
                      .format(func.start_ea))
            else:
                print('\t[+] "{0}" à 0x{1:x}'.format(wrapper_name, func.start_ea))
                ptr_ea = idc.get_operand_value(func.start_ea, 1)
                if ptr_ea != idc.BADADDR:
                    idc.set_name(ptr_ea, 'fn_' + base, NAME_FLAGS)

        lst = dynamic_api.setdefault(dll_name, [])
        if fn_name not in lst:
            lst.append(fn_name)
            count += 1

    print('Printing dynamically loaded API ({0} total)...'.format(count))
    print_api(dynamic_api)


main()
