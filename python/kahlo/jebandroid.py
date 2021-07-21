#
# jebandroid : Signature scheme for interoperability with JEB, on Android targets
#

from . import signature
from . import android

class Exn(Exception): pass
class ConversionExn(Exn): pass

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

class JebAndroidScheme(signature.Scheme):
    def __init__(self, translator=None):
        super().__init__(android.Signature,
                         formatter=JebFormatter.singleton,
                         translator=translator)
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
    return android.MethodSignature(tok.cls, _meth_name_from_jeb(tok.method), tok.params, tok.retty)
#enddef

# XXX: Leaving out field signatures for now.

JebSignature = JebMethodSignature | JebClassSignature
