# -*- mode: poly-pyjs -*-
#
# kahlo example
#

import kahlo

# Example of how to use the BaseRPC class.
class TestRPC(kahlo.rpc.BaseRPC):

    agent_add = kahlo.rpc.agentcall('''//JS
    function (foo, bar) {
       return foo + bar;
    }
    ''')

    agent_mult = kahlo.rpc.agentcall('''//JS
    function (a, b) {
        return a * b;
    }
    ''')

    agent_callback = kahlo.rpc.agentcall('''//JS
    async function (x, y) {
        console.log("Calling host_add.");
        var rv = await kahlo.hostcall.host_add(x, y);
        console.log("Got back value = " + rv);
        return rv;
    }
    ''')

    
    @kahlo.rpc.hostcall
    def host_add(self, ding, dong):
        print("Called host_add with {} + {} = {}".format(ding, dong, ding+dong))
        return ding + dong
    #enddef

    @kahlo.rpc.hostcall
    def host_mult(self, c, d):
        print("Called host_mult with {} * {} = {}".format(c, d, c*d))
        return c * d
    #enddef

    @kahlo.rpc.hostcall
    def host_callback(self, v):
        print("Called host_callback with v = {!r}".format(v))
        return v + 20
    #enddef
    
    async def normal_func(self, foo, bar):
        rv = await self.agentcall.agent_callback(foo, bar)
        print("Got rv = {!r}".format(rv))
    #enddef

#endclass

##############################################3


class TestSig(kahlo.signature.AbstractSignature):
    def __init__(self, name, value):
        self.name = name
        self.value = value
    #enddef
    def to_frida(self): return "{} = {}".format(self.name, self.value)
    @classmethod
    def from_frida(cls, s):
        (n, v) = (x.strip() for x in s.split("="))
        return cls(n, v)
    #enddef
#endclass

class TestFormatter(kahlo.signature.Formatter):
    def __init__(self): super().__init__(TestSig)
    def to_disp(self, sig):
        return "{} -> {}".format(sig.name, sig.value)
    #enddef
    def from_disp(self, s):
        (n, v) = (x.strip() for x in s.split("->"))
        return self.sigcls(n, v)
    #enddef
#endclass

class TestTranslator(kahlo.signature.Translator):
    def __init__(self, rtprefix):
        self.rtprefix = rtprefix
    #enddef

    def to_runtime(self, sig): return TestSig(self.rtprefix + sig.name, sig.value)
    def to_logical(self, sig): return TestSig(sig.name[len(self.rtprefix):], sig.value)
#endclass

test_scheme = kahlo.signature.Scheme(TestSig, TestFormatter(), TestTranslator("XXX_"))
