#
# jebandroid : Signature scheme for interoperability with JEB, on Android targets
#

import json

from . import signature
from . import android

class Exn(Exception): pass

class ConversionExn(Exn): pass

class TranslatorExn(Exn): pass

class InspectorExn(Exn): pass
class UnknownSignatureExn(InspectorExn): pass

class SchemeExn(Exn): pass

_special_name_map = {
    "$init" : "<init>",
    "$clinit" : "<clinit>",
}
_rev_special_name_map = dict(((v, k) for (k, v) in _special_name_map.items()))
   
def _meth_name_to_jeb(name):
    return _special_name_map[name] if name in _special_name_map else name
#enddef
def _meth_name_from_jeb(name):
    return _rev_special_name_map[name] if name in _rev_special_name_map else name
#enddef

class JebFormatter(signature.Formatter):
    def __init__(self): super().__init__(android.Signature)

    def to_disp(self, sig):
        if isinstance(sig, android.ClassSignature):
            return sig.to_jvm()
        elif isinstance(sig, android.MethodSignature):
            return "{}->{}({}){}".format(
                sig.clsty.to_jvm(),
                _meth_name_to_jeb(sig.name),
                "".join((ty.to_jvm() for ty in sig.params)),
                sig.retty.to_jvm())
        elif isinstance(sig, android.FieldSignature):
            return "{}->{}:{}".format(
                sig.clsty.to_jvm(),
                sig.name,
                sig.ty.to_jvm())
        else:
            # Shouldn't be the case.
            assert False
        #endif
    #enddef

    def from_disp(self, s):
        return JebSignature.parseString(s, parseAll=True)[0]
    #enddef
   
#endclass
JebFormatter.singleton = JebFormatter()

# This class can also be used as an inspector to retrieve additional details about a signature.
class JebTranslator(signature.Translator, signature.Inspector):

    # Note: This class always ignores misses as that is the design of the translation map.
    def __init__(self, mapfile, sigcls=android.Signature, formatter=JebFormatter.singleton):
        assert(issubclass(sigcls, android.Signature))
        super().__init__(sigcls)
        self.formatter = formatter
        self.mapfile = mapfile
        self.load_map()
    #enddef

    def load_map(self):

        with open(self.mapfile) as f:
            self.full_map = json.loads(f.read())
        #endwith

        self.rtl_lookup = {}
        for (lclssig, lclsinfo) in self.full_map.items():
            rclssig = lclsinfo["runtime_sig"]
            self.rtl_lookup[rclssig] = lclssig
        #endfor
    #enddef      

    def _get_info(self, sig_from : android.Signature):

        disp_from = self.formatter.to_disp(sig_from)

        cls_sig = sig_from.get_class_sig()
        cls_disp = self.formatter.to_disp(cls_sig)
        if cls_disp in self.full_map:
            cls_info = self.full_map[cls_disp]
        else:
            return None
        #endif

        if isinstance(sig_from, android.ClassSignature):
            return cls_info
        elif isinstance(sig_from, android.MethodSignature):
            if disp_from in cls_info["methods"]:
                meth_info = cls_info["methods"][disp_from]
                return meth_info
            else:
                return None
            #endif
        elif isinstance(sig_from, android.FieldSignature):
            field_name = sig_from.name
            if field_name in cls_info["fields"]:
                field_info = cls_info["fields"]["field_name"]
                if field_info["logical_sig"] != disp_from:
                    raise TranslatorExn("Field signature conflict: expected {}, got {}".format(disp_from, field_info["logical_sig"]))
                return field_info
            else:
                return None
            #endif
        else:
            raise TranslatorExn("Unsupported signature type: {!r}".format(type(sig_from)))
        #endif
    #enddef

    def to_runtime(self, lsig):
        info = self._get_info(lsig)
        return self.formatter.from_disp(info["runtime_sig"]) if info != None else lsig
    #enddef

    def to_logical(self, rsig):

        rdisp = self.formatter.to_disp(rsig)
        
        rcls_disp = self.formatter.to_disp(rsig.get_class_sig())
        if not rcls_disp in self.rtl_lookup: return rsig

        lcls_disp = self.rtl_lookup[rcls_disp]
        lcls_sig = self.formatter.from_disp(lcls_disp)
        lcls_info = self._get_info(lcls_sig)
        if lcls_info == None: return rsig

        if isinstance(rsig, android.ClassSignature):
            return lcls_sig
        elif isinstance(rsig, android.MethodSignature):
            for (lmeth_sig, lmeth_info) in lcls_info["methods"].items():
                if lmeth_info["runtime_sig"] == rdisp:
                    return self.formatter.from_disp(lmeth_sig)
                #endif
            #endfor
            return rsig
            
        elif isinstance(rsig, android.FieldSignature):
            for (lfield_sig, lfield_info) in lcls_info["fields"].items():
                if lfield_info["runtime_sig"] == rdisp:
                    return self.formatter.from_disp(field_sig)
                #endif
            #endfor
            return rsig

        else:
            raise TranslatorExn("Unsupported signature type: {!r}".format(type(sig_from)))
        #endif
        
    #enddef
    
    def has_details(self, sig):
        return self._get_info(sig) != None
    #enddef
    
    def get_details(self, sig):
        info = self._get_info(sig)
        if info == None:
            raise UnknownSignatureExn("Cannot get details of unknown signature {}".format(self.formatter.to_disp(sig)))
        #endif
        return info
    #enddef
    
#endclass

class JebAndroidScheme(signature.Scheme):
    def __init__(self, mapfile=None, translator=None, inspector=None):
        if mapfile != None:
            if translator == None:
                translator = JebTranslator(mapfile)
            else:
                raise SchemeExn("Only one of mapfile or translator can be specified.")
            #endif
        #endif
        if inspector == None and isinstance(translator, JebTranslator):
            inspector = translator
        #endif
       
        super().__init__(android.Signature,
                         formatter=JebFormatter.singleton,
                         translator=translator,
                         inspector=inspector)
    #enddef
#endclass

#
# JEB SIGNATURE STRING PARSER
#

import pyparsing as pp

# Helper decorator for creating parsers.
def parser(ppelem):
    def _decorator(func):
        ppelem.setParseAction(func)
        return ppelem
    #enddef
    return _decorator
#enddef

supp = pp.Suppress

@parser(pp.oneOf(android.PrimitiveType._code_map.values()))
def JebPrimitive(tok):
    r = [k for (k,v) in android.PrimitiveType._code_map.items() if v == tok[0]]
    if r == []: raise ConversionExn(
            "Could not convert string {!r} to a primitive type".format(s)
    )
    return android.PrimitiveType(r[0])
#enddef

JebIdentifier = pp.Word(pp.alphas + "_<>$", bodyChars=pp.alphanums + "_<>/$")

@parser(supp("L") + JebIdentifier("name") +  supp(";"))
def JebCls(tok):
    return android.ClsType(tok.name.replace("/", "."))
#enddef

# TypeName is used in Array
JebTypeName = pp.Forward()

@parser(supp("[") + JebTypeName("ty"))
def JebArray(tok):
    return android.ArrayType(tok.ty)
#enddef

JebTypeName << (JebPrimitive | JebCls | JebArray)

JebParameterList = supp("(") + pp.ZeroOrMore(JebTypeName) + supp(")")

@parser(JebCls.copy())
def JebClassSignature(tok):
    return android.ClassSignature(android.ClsType(tok[0].replace("/", ".")))
#enddef

@parser(JebCls("cls") + supp("->") + JebIdentifier("method") + JebParameterList("params") + JebTypeName("retty"))
def JebMethodSignature(tok):
    return android.MethodSignature(tok.cls, _meth_name_from_jeb(tok.method), list(tok.params), tok.retty)
#enddef

@parser(JebCls("cls") + supp("->") + JebIdentifier("name") + supp(":") + JebTypeName("ty"))
def JebFieldSignature(tok):
    return android.FieldSignature(tok.cls, tok.name, tok.ty)
#enddef

JebSignature = JebMethodSignature | JebFieldSignature | JebClassSignature
