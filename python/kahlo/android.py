#
# android : Classes specific to Android
#

import enum

from . import signature

class SigKind(enum.Enum):
    CLS = 0
    METHOD = 1
#endclass

class Type(object): pass

class PrimitiveType(Type):
    _code_map = {
        "byte" : "B",
        "char" : "C",
        "double" : "D",
        "float" : "F",
        "int" : "I",
        "long" : "J",
        "short" : "S",
        "boolean" : "Z",
        "void" : "V"
    }
    def __init__(self, name):
        self.name = name
    #enddef
    def to_frida(self): return self.name
    def to_jvm(self): return self._code_map[self.name]

    @classmethod
    def from_jvm(cls, s):
        r = [k for (k,v) in cls._code_map.items() if v == s]
        if r == []: raise ConversionExn(
                "Could not convert string {!r} to a primitive type".format(fridastr)
        )
        return cls(r[0])

        
#endclass

class ClsType(Type):
    def __init__(self, name):
        self.name = name
    #enddef
    def to_frida(self): return self.name
    def to_jvm(self): return "L{};".format(self.name.replace(".", "/"))
#enddef

class ArrayType(Type):
    def __init__(self, basety : Type):
        self.basety = basety
    #enddef
    def to_jvm(self): return "[" + self.basety.to_jvm()
    # Somehow frida expects a JVM-style type name for arrays?
    def to_frida(self): return self.to_jvm()
#endclass

class Signature(signature.AbstractSignature):
    @classmethod
    def from_frida(cls, s):
        return FridaJavaSignature.parseString(s, parseAll=True)[0]
    #enddef
#endclass

class ClassSignature(Signature):
    def __init__(self, clsty : ClsType):
        self.kind = SigKind.CLS
        self.clsty = clsty
    #enddef
    @property
    def name(self): return self.clsty.name

    def to_frida(self): return self.clsty.to_frida()
    def to_jvm(self): return self.clsty.to_jvm()

#endclass

class MethodSignature(Signature):
    _properties = ("clsty", "name", "params", "retty")

    def __init__(self, **kwargs):
        self.kind = SigKind.METHOD
        super().__init__(**kwargs)
    #enddef


    
    def __init__(self, clsty : ClsType, name, params, retty : Type):
        self.kind = SigKind.METHOD
        self.clsty = clsty
        self.name = name
        self.params = params
        self.retty = retty
    #enddef

    def to_frida(self):
        return "{}.{}({}): {}".format(
            self.clsty.to_frida(),
            self.name,
            ", ".join((ty.to_frida() for ty in self.params)),
            self.retty.to_frida()
        )
    #enddef

    def to_jvm(self):
        return "{}->{}({}){}".format(
            self.clsty.to_jvm(),
            self.name,
            "".join((ty.to_jvm() for ty in self.params)),
            self.retty.to_jvm()
        )
    #enddef

#endclass

# XXX: No signature for fields right now.

#
# PARSERS FOR FRIDA JAVA SIGNATURE STRINGS
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

@parser(pp.oneOf(PrimitiveType._code_map.keys()))
def FridaJavaPrimitive(tok):
    return PrimitiveType(tok[0])
#enddef

FridaJavaBaseIdentifier = pp.Word(pp.alphas + "_$", bodyChars=pp.alphanums + "_$")

FridaJavaIdentifier = pp.delimitedList(FridaJavaBaseIdentifier, ".", combine=True)

@parser(FridaJavaIdentifier("name"))
def FridaJavaCls(tok):
    return ClsType(tok.name)
#enddef

@parser((FridaJavaPrimitive | FridaJavaCls)("base") +
        pp.ZeroOrMore(pp.Literal("[]"))("brackets"))
def FridaJavaTypeName(tok):
    if tok.brackets == "":
        return tok.base
    else:
        ty = tok.base
        for _ in range(0, len(tok.brackets)):
            ty = ArrayType(ty)
        #endfor
        return ty
    #endif
#enddef

FridaJavaParameterList = supp("(") + \
    pp.Optional(pp.delimitedList(FridaJavaTypeName, ",")) + \
    supp(")")

@parser(FridaJavaIdentifier("name"))
def FridaJavaClassSignature(tok):
    return ClassSignature(ClsType(tok.name))
#enddef

# XXX: We don't have an implementation of FridaJavaFieldSignature currently
# because it's not clear what the syntax should look like.

@parser((FridaJavaBaseIdentifier + supp(".") +
         pp.delimitedList(FridaJavaBaseIdentifier, "."))("methodpath") +
        FridaJavaParameterList("params") +
        supp(":") + FridaJavaTypeName("retty")
        )
def FridaJavaMethodSignature(tok):
    method_name = tok.methodpath[-1]
    class_name = ".".join(tok.methodpath[:-1])
    clsty = FridaJavaCls.parseString(class_name, parseAll=True)[0]
    return MethodSignature(clsty, method_name, tok.params, tok.retty)
#enddef

FridaJavaSignature = FridaJavaMethodSignature | FridaJavaClassSignature
