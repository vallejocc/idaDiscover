#
# idaDiscover plugin - by Javier Vicente Vallejo - @vallejocc
#

import os
from ida_defines import *
import binascii

class Utils():

    ################################################################################################
    @staticmethod
    def doprint(s): print(s)
    @staticmethod
    def recursive_print(src, dpth = 0, key = '', printfunc=None):
        if not printfunc: printfunc = Utils.doprint
        tabs = lambda n: ' ' * n * 4 # or 2 or 8 or...
        brace = lambda s, n: '%s%s%s' % ('['*n, s, ']'*n)
        if isinstance(src, dict):
            for key, value in src.iteritems():
                printfunc(tabs(dpth) + brace(key, dpth))
                Utils.recursive_print(value, dpth + 1, key)
        elif isinstance(src, list):
            for litem in src: Utils.recursive_print(litem, dpth + 2)
        else:
            if key: printfunc(tabs(dpth) + '%s = %s' % (key, src))
            else: printfunc(tabs(dpth) + '- %s' % src)

    ################################################################################################
    @staticmethod
    def loopsInFunc(funcea):
        loops = []
        func_end = IDAAPI_FindFuncEnd(funcea)
        for item in IDAAPI_FuncItems(funcea):
            for xref in IDAAPI_XrefsTo(item, 0):
                if xref.type not in [1,21]:
                    if funcea <= xref.to <= xref.frm <= func_end:
                        if IDAAPI_GetMnem(xref.frm) not in ['call', 'retn']:
                            loops.append((xref.frm, xref.to))
        if len(loops) > 0:
            return loops
        else:
            return False

    ################################################################################################
    @staticmethod
    def GetExePath():
        if os.path.exists(IDAAPI_GetInputFilePath()):
            print("Binary: %s" % IDAAPI_GetInputFilePath())
            return IDAAPI_GetInputFilePath()
        print("Unable to locate original input binary")
        idbPath = IDAAPI_GetIdbPath()
        idbDir = os.path.abspath(os.path.dirname(idbPath))
        idbNoExt = idbPath[len(idbDir)+1:-4]
        for e in os.listdir(idbDir):
            if idbNoExt in e and \
               ".i64" not in e and \
               ".id" not in e and \
               ".nam" not in e and \
               ".til" not in e:
                exePath = idbDir+"//"+e
                if os.path.exists(exePath):
                    print("Binary: %s" % exePath)
                    return exePath
        print("Unable to locate binary related to this idb")
        return None
    
    ################################################################################################
    @staticmethod
    def ReplaceAliasesAndPrepareString(s):
        s=s.replace("%~dp0", os.path.dirname(os.path.realpath(__file__)))
        return s
        
    ################################################################################################
    @staticmethod
    def GetIniFilePath():
        return '%s/idadiscover.ini' % os.path.abspath(os.path.dirname(__file__))

    ################################################################################################
    @staticmethod
    def OpenWriteIniFilePath():
        return open(Utils.GetIniFilePath(), "w+b")

    ################################################################################################
    @staticmethod
    def BinarySearch(alist, item):
        first = 0
        last = len(alist)-1
        found = False
        while first<=last and not found:
            pos = 0
            midpoint = (first + last)//2
            if alist[midpoint] == item:
                pos = midpoint
                found = True
            else:
                if item < alist[midpoint]:
                    last = midpoint-1
                else:
                    first = midpoint+1
        return (pos, found)

    ################################################################################################
    @staticmethod
    def Chunks(l, n):
        for i in range(0, len(l), n):
            yield l[i:i+n]

    ################################################################################################
    @staticmethod
    def ShowDataAndAskSave(tag, data, path=None):
        print(tag, ":")
        print("--------------------------------")
        for c in Utils.Chunks(data, 16):
            print(binascii.hexlify(c))
        if not path: path = IDAAPI_AskFile(True, '*.*', 'Enter path to save...')
        print("Saving to file %s" % path)
        if path:
            f = open(path, "wb")
            f.write(data)
            f.close()

    ################################################################################################
    @staticmethod
    def AskDirectory(msg = None):
        if not msg: v = IDAAPI_AskStr("", "Please enter the path of the directory")
        else: v = IDAAPI_AskStr("", msg)
        return v

    ################################################################################################
    @staticmethod
    def AskFileAndRead():
        path = IDAAPI_AskFile(False, '*.*', 'Enter path to read...')
        print("Reading from file %s" % path)
        if path:
            f = open(path, "rb")
            data = f.read()
            f.close()
            return data
        return None

    ################################################################################################
    @staticmethod
    def AskAddressRange():
        start = IDAAPI_AskLong(0, "Enter starting address")
        end = IDAAPI_AskLong(0, "Enter ending address")
        return (start, end)

    ################################################################################################
    @staticmethod
    def AskSize():
        size = IDAAPI_AskLong(0, "Enter size")
        return size

    ################################################################################################
    @staticmethod
    def AskLongValue(msg):
        v = IDAAPI_AskLong(0, "Enter integer value - " + msg)
        return v

    ################################################################################################
    @staticmethod
    def AskTextValue(msg):
        v = IDAAPI_AskStr("", "Enter text value - " + msg)
        return v

    ################################################################################################
    @staticmethod
    def AskYN(msg):
        if IDAAPI_AskYN (1, msg) == 1: return "yes"
        return "no"

    ################################################################################################
    @staticmethod
    def EscapeNonReadableCharacters(s):
        sout = ""
        for e in s:
            if ord(e)>=0x20 and ord(e)<=0x7e:
                if e=="\\": sout += "\\\\"
                else: sout += e
            else:
                sout += "\\x%x" % ord(e)
        return sout

    ################################################################################################
    @staticmethod
    def UnescapeSeqHexa(s):
        out = ""
        hexa = "0123456789abcdefABCDEF"
        eqix = "xX"
        i=0
        while i<len(s):
            if s[i]=="\\" and i<len(s)-3 and s[i+1] in eqix and s[i+2] in hexa and s[i+3] in hexa:
                out += chr(int(s[i+2:i+4], 16)&0xff)
                i+=4
            elif s[i]=="\\" and i<len(s)-1 and s[i+1]=="\\":
                out += "\\"
                i+=2
            else:
                out += s[i]
                i+=1
        return out

    ################################################################################################
    @staticmethod
    def AskStringUnescapeSeqHexa():
        s = IDAAPI_AskStr("", "Enter string (accepted escape seq hex i.e. aaaaa\\x32aaa\\x31aaa = aaaaa2aaa1aaa")
        return Utils.UnescapeSeqHexa(s)

    ################################################################################################
    @staticmethod
    def GetOperandsTxtFromInsTxt(instxt):
        if not " " in instxt: return (None, None, None)
        instxt = instxt[instxt.index(" ")+1:]
        if ";" in instxt: instxt = instxt[:instxt.index(";")]
        instxt=instxt.replace(" ", "")
        if not "," in instxt: return (instxt, None, None)
        l = instxt.split(",")
        if len(l)==2: return (l[0], l[1], None)
        if len(l)==3: return (l[0], l[1], l[2])
        return (None, None, None)

    ################################################################################################
    @staticmethod
    def PrintableChars(s):
        sout = ""
        valid = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%&/()=?[]\\{}-_<>*.:,;|\""
        for b in s:
            if b in valid: sout+=b
            else: sout+="."
        return sout

    ################################################################################################
    @staticmethod
    def GetIDANames(bNoCode=False):
        ret = []
        for segea in Segments():
            for ea in range(segea, IDAAPI_SegEnd(segea)):#IDAAPI_Heads(segea, IDAAPI_SegEnd(segea)):
                if (bNoCode and IDAAPI_IsCode(IDAAPI_GetFlags(ea))): continue
                res = None
                #res = IDAAPI_get_func_name(ea)
                #if res is None: res = IDAAPI_get_name(-1, ea)
                if res is None: res = IDAAPI_get_true_name(ea, ea)
                if res and len(res): ret.append((ea, res))
        return ret

    ################################################################################################
    @staticmethod
    def GetIDAHeads():
        ret = []
        for segea in Segments():
            for ea in IDAAPI_Heads(segea, IDAAPI_SegEnd(segea)):    
                ret.append(ea)
        return ret

    ################################################################################################
    @staticmethod
    def GetIDAHeadsDisasm():
        ret = []
        for segea in Segments():
            for ea in IDAAPI_Heads(segea, IDAAPI_SegEnd(segea)):    
                ret.append((ea, IDAAPI_GetDisasm(ea)))
        return ret
    
    ################################################################################################
    @staticmethod
    def GetIDANamesAddressesList(bNoCode=False):
        ret = []
        for e in Utils.GetIDANames(bNoCode=bNoCode):
            ret.append(e[0])
        return ret

    ################################################################################################
    @staticmethod
    def GetIDANamesContentsList(sz, bNoCode=False):
        ret = []
        lnames = Utils.GetIDANames(bNoCode=bNoCode)
        for i in range(0, len(lnames)):
            if sz == -1 or sz==-2: #negative values means, take the full block of data until the next ida name or end
                if i+1<len(lnames): temp=lnames[i+1][0]-lnames[i][0]
                else: temp=IDAAPI_SegEnd(lnames[i][0])-lnames[i][0]
            else:
                temp = sz
            data = ""
            while temp:
                try:
                    data = IDAAPI_GetManyBytes(lnames[i][0], temp)
                    break
                except:
                    temp-=1
            if sz == -2: #this option (given as size) means remove trailing zeros
                while len(data) and ord(data[-1])==0:
                    data = data[0:-1]
            if len(data):
                ret.append({"addr":lnames[i][0], "sz":len(data), "content":data})
        return ret

    ################################################################################################
    @staticmethod
    def GetInstructionsImmOperandsList():
        ret = []
        for segea in Segments():
            for head in IDAAPI_Heads(segea, IDAAPI_SegEnd(segea)):
                if IDAAPI_IsCode(IDAAPI_GetFlags(head)):
                    op0t = IDAAPI_GetOpType(head, 0)
                    op1t = IDAAPI_GetOpType(head, 1)
                    if op0t==5 or op0t==6 or op0t==7: ret.append(IDAAPI_GetOperandValue(head, 0))
                    if op1t==5 or op1t==6 or op1t==7: ret.append(IDAAPI_GetOperandValue(head, 1))
        return ret

    ################################################################################################
    @staticmethod
    def Quote(s):
        if len(s) and s[0]=='\'' and s[-1]=='\'':
            return s
        if len(s) and s[0]=='\"' and s[-1]=='\"':
            return s
        return "\""+s+"\""

    ################################################################################################
    @staticmethod
    def UnQuote(s):
        if not len(s):return s
        if s[0]=='\"' and s[-1]=='\"':
            return s[1:-1]
        if s[0]=='\'' and s[-1]=='\'':
            return s[1:-1]
        return s
    
    ################################################################################################
    @staticmethod
    def GetPlatform():
        info = IDAAPI_get_inf_structure()
        if info.is_64bit():
            bits = 64
        elif info.is_32bit():
            bits = 32
        else:
            bits = 16
        return bits
