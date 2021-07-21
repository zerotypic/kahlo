#
# signature : Unique identifiers for classes, methods and fields.
#

import enum

__all__ = ("AbstractSignature", "Formatter", "FridaFormatter",
           "Translator", "IdentTranslator", "Scheme")

class Exn(Exception): pass

class AbstractSignature(object):
    _scheme = None
    
    def to_frida(self): raise NotImplementedError("to_frida not implemented.")
    @classmethod
    def from_frida(cls, s): raise NotImplementedError("from_frida not implemented.")

    # Note: The below convenience functions only work if _scheme is set on the signature.
    def to_runtime(self): return self._scheme.to_runtime(self)
    def to_logical(self): return self._scheme.to_logical(self)
    def to_disp(self): return self._scheme.to_disp(self)
    @classmethod
    def from_disp(cls, s): return cls._scheme.from_disp(cls, s)   

#endclass

class Formatter(object):
    def __init__(self, sigcls):
        self.sigcls = sigcls
    #enddef
    def to_disp(self, sig): raise NotImplementedError("to_disp not implemented.")
    def from_disp(self, s): raise NotImplementedError("from_disp not implemented.")
#endclass

class FridaFormatter(Formatter):
    def to_disp(self, sig): return sig.to_frida()
    def from_disp(self, s): self.sigcls.from_frida(s)
#endclass

class Translator(object):
    def __init__(self, sigcls):
        self.sigcls = sigcls
    #enddef

    def to_runtime(self, sig): raise NotImplementedError("to_runtime not implemented")
    def to_logical(self, sig): raise NotImplementedError("to_logical not implemented")
#endclass

class IdentTranslator(Translator):
    def __init__(self): super().__init__(AbstractSignature)
    def to_runtime(self, sig): return sig
    def to_logical(self, sig): return sig
#endclass
IdentTranslator.singleton = IdentTranslator()

class Scheme(object):

    def __init__(self, sigcls, formatter=None, translator=None):
        if formatter == None: formatter = FridaFormatter(sigcls)
        if translator == None: translator = IdentTranslator.singleton

        self.sigcls = sigcls
        self.formatter = formatter
        self.translator = translator
    #enddef

    def _set_scheme(self, sig):
        sig._scheme = self
        return sig
    #enddef
    
    def to_disp(self, sig): return self.formatter.to_disp(sig)
    def from_disp(self, s): return self._set_scheme(self.formatter.from_disp(s))
    def to_runtime(self, sig): return self._set_scheme(self.translator.to_runtime(sig))
    def to_logical(self, sig): return self._set_scheme(self.translator.to_logical(sig))

#endclass   
