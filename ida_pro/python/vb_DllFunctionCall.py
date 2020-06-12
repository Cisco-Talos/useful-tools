################################################################################
#
#   Copyright (C) 2014  Cisco Systems, Inc./SourceFire, Inc.
#
#   Author: Angel M. Villegas (anvilleg [at] sourcefire [dot] com)
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
#   Last Modified: August 8, 2014
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

import idaapi
import idautils

#   Print out dynamically loaded API
def printAPI(data):
    formatStr = '{0:25} {1}'
    for dll in sorted(data.keys()):
        for fn in sorted(data[dll]):
            print formatStr.format(dll, fn)

#   Find the start of the function
#   Expects ea to be the address of loc_XXXXXX
def defineFunction(ea):
    #   Function follows the format:
    #       mov     eax, dword_ZZZZZZZZ
    #       or      eax, eax
    #       jz      short loc_XXXXXXXX
    #       jmp     eax
    # loc_XXXXXX:
    #       push    YYYYYYYYh
    #       mov     eax, offset DllFunctionCall
    #       call    eax ; DllFunctionCall
    #       jmp     eax

    jmpInstr = DecodePreviousInstruction(ea).ea
    jzInstr = DecodePreviousInstruction(jmpInstr).ea
    orInstr = DecodePreviousInstruction(jzInstr).ea
    movInstr = DecodePreviousInstruction(orInstr).ea
    if (GetMnem(jmpInstr) != 'jmp') and (GetMnem(jzInstr) != 'jz') and \
        (GetMnem(orInstr) != 'or') and (GetMnem(movInstr) != 'mov'):
        print '\t[!] Error: Unable to find function start address'

    if 0 == MakeFunction(movInstr):
        print '\t[!] Error: Unable to define function at 0x{0:h}'.format(movInstr)


def createDllFunctionCallStruct():
    #   Create DllFunctionCall argument sub structure
    subStructId = AddStrucEx(-1, HANDLES_STRUCT_NAME, 0)
    AddStrucMember(subStructId, 'hModule', 0x4, FF_DWRD | FF_DATA, -1, 4)
    AddStrucMember(subStructId, 'fnAddress', 0x8, FF_DWRD | FF_DATA, -1, 4)

    #   Create DllFunctionCall argument structure
    structId = AddStrucEx(-1, DLL_FUNCTION_CALL_STRUCT_NAME, 0)
    AddStrucMember(structId, 'lpDllName', 0x0, FF_DWRD | FF_0OFF | FF_DATA,
                    -1, 4)
    AddStrucMember(structId, 'lpExportName', 0x4, FF_DWRD | FF_0OFF | FF_DATA,
                    -1, 4)
    AddStrucMember(structId, 'sizeOfExportName', 0xA, FF_BYTE | FF_DATA, -1, 1)
    AddStrucMember(structId, 'ptrHandles', 0xC, FF_DWRD | FF_0OFF | FF_DATA, -1, 4)


DLL_FUNCTION_CALL_STRUCT_NAME = 'DllFunctionCallStruct'
HANDLES_STRUCT_NAME = 'DynamicHandles'
dynamicAPI = {}
loadAPI = 0

print "Starting..."

#   Check if struct exists, if not, create it
structId = GetStrucIdByName(DLL_FUNCTION_CALL_STRUCT_NAME)
if BADADDR == structId:
    print '\t[+] Structure "{0}" does not exist, creating structure...'.format(
            DLL_FUNCTION_CALL_STRUCT_NAME)
    structId = createDllFunctionCallStruct()

for xref in idautils.CodeRefsTo(LocByName('DllFunctionCall'), 1):
    instr =  xref
    prevInstr = DecodePreviousInstruction(xref).ea
    structInstr = DecodePreviousInstruction(prevInstr).ea

    #   The instruction should be push 0x????????
    if GetMnem(structInstr) == 'push' and GetOpType(structInstr, 0) == 0x05:
        #   Set the operand type to an offset
        OpOff(structInstr, 0, 0)

        #   Get struct offset and apply structure to it
        structOffset = GetOperandValue(structInstr, 0)
        MakeUnkn(structOffset, 0)
        MakeStruct(structOffset, DLL_FUNCTION_CALL_STRUCT_NAME)
        strOffset = Dword(structOffset)
        lpDllName = GetString(strOffset, -1, ASCSTR_TERMCHR)
        MakeUnkn(strOffset, 0)
        MakeStr(strOffset, strOffset + len(lpDllName))
        strOffset = Dword(structOffset + 4)
        lpFunctionName = GetString(strOffset, -1, ASCSTR_TERMCHR)
        MakeStr(strOffset, strOffset + len(lpFunctionName))
        MakeName(structOffset, 'struct{0}'.format(lpFunctionName))

        #   Get sub structure address, apply structure, and apply name to it
        subStructAddr = Dword(structOffset + 0xC)
        MakeStruct(subStructAddr, HANDLES_STRUCT_NAME)
        MakeName(subStructAddr, 'subStruct{0}'.format(lpFunctionName))

        #   Check if a function is already defined
        if '' == GetFunctionName(structInstr):
            print '\t[+] Function was not defined, creating function ...'
            defineFunction(structInstr)

        #   Redefine function name to something more descriptive
        lpFnName = '{0}_wrapper'.format(lpFunctionName)
        fnAddress = idaapi.get_func(structInstr).startEA
        if not MakeName(fnAddress, lpFnName):
            print '\t[!] Error: Failed to set function name'
        else:
            print '\t[+] Function "{0}" set at 0x{1:x}'.format(lpFnName,
                    fnAddress)
            MakeName(GetOperandValue(fnAddress, 1),
                        'fn{0}'.format(lpFunctionName))

        #   Add API to dynamically loaded API
        if lpDllName not in dynamicAPI:
            dynamicAPI[lpDllName] = []
        if lpFunctionName not in dynamicAPI[lpDllName]:
            dynamicAPI[lpDllName].append(lpFunctionName)
            loadAPI += 1

print 'Printing dynamically loaded API ({0} total)...'.format(loadAPI)
printAPI(dynamicAPI)
