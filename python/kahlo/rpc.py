# -XXX*- mode: poly-pyjs -*-
#
# rpc : Base RPC mechanism for kahlo
#

import string
import enum
import json
import asyncio
import threading
import frida

from . import scribe

__all__ = ("BaseRPC",)

class Exn(Exception): pass
class InvalidIdExn(Exn): pass
class ContextManagerExn(Exn): pass
class ImportConflictExn(Exn): pass

class Context(object):

    def __init__(self, manager, rpcid):
        self.manager = manager
        self.rpcid = rpcid
        self.result = None
        self.result_ev = asyncio.Event()
    #enddef

    def set_result(self, result):
        self.result = result
        self.manager._event_loop.call_soon_threadsafe(self.result_ev.set)
    #enddef

    async def completed(self):
        if asyncio.get_running_loop() != self.manager._event_loop:
            print("WARNING: Event loops are different:")
            print("\tCaller: {!r} ({:x})".format(asyncio.get_running_loop(), hash(asyncio.get_running_loop())))
            print("\t   ctx: {!r} ({:x})".format(self.manager._event_loop, hash(self.manager._event_loop)))
        #endif
        await self.result_ev.wait()
        return self.result
    #enddef

    def is_complete(self): return self.result_ev.is_set()
            
#endclass

class ContextManager(object):

    def __init__(self, evloop=None):
        self._rpcid_counter = 1
        self._contexts = {}
        self._event_loop = evloop if evloop != None else asyncio.get_event_loop()
        self._threadlock = threading.Lock()
    #enddef

    def _get_rpcid(self):
        with self._threadlock:
            rpcid = self._rpcid_counter
            self._rpcid_counter += 1
            return rpcid
        #endwith
    #enddef
    
    def create_context(self):
        rpcid = self._get_rpcid()
        ctx = Context(self, rpcid)
        self._contexts[rpcid] = ctx
        return ctx
    #enddef

    def clear_context(self, ctx):
        if ctx.rpcid in self._contexts:
            if ctx == self._contexts[ctx.rpcid]:
                del self._contexts[ctx.rpcid]
            else:
                raise ContextManagerExn("Context being cleared does not match context in manager!")
            #endif
        else:
            raise ContextManagerExn("Context being cleared is not in manager.")
        #endif
    #enddef
    
    def set_context_result(self, rpcid, result):
        if rpcid in self._contexts:
            self._contexts[rpcid].set_result(result)
            # XXX: Do we need to cleanup self._contexts?
        else:
            raise InvalidIdExn("Unknown RPCID {}".format(rpcid))
        #endif
    #enddef
    
#endclass

# class CallDirection(enum.Enum):
#     AGENT = 1
#     HOST = 2
# #endclass

# Only used by the agentcall function and hostcall decorator below.

# class RPCall(object):
#     def __init__(self, direction, *args):
#         self.direction = direction
#         self.args = args
#     #enddef
# #endclass

class RPCall(object): pass

class HostRPCall(RPCall):
    def __init__(self, func):
        self.func = func
    #enddef
#endclass

class AgentRPCall(RPCall):
    def __init__(self, script, wrapfunc=None, imports=None):
        self.script = script
        self.wrapfunc = wrapfunc
        self.imports = imports
    #enddef

    # Decorator to set wrapper function
    def wrapper(self, wrapfunc):
        self.wrapfunc = wrapfunc
        return self
    #enddef
#endclass


def agentcall(script):
    '''Function for defining functions running on the agent that can be called
    from the host.

    Only meant to be used within a `BaseRPC` subclass definition. The string
    argument acts as the source of the Javascript function running on the
    agent.

    The returned AgentRPCall object has a decorator `wrapper`, which can be
    used to define a wrapper function.

    The wrapper function must accept as its first argument an asynchronous
    function `do_agentcall`, which when called will run the aforementioned
    Javascript function on the agent, and return the value obtained from that
    function. It is the responsibility of the wrapper to call `do_agentcall`,
    to pass it the appropriate arguments, and to return the value obtained
    from the call, modified as required.

    To call the function, use the `BaseRPC.agentcall` object: call function
    `foo` as `rpc_object.agentcall.foo(arg, ...)`. Note that the function is
    asynchronous.

    '''
    return AgentRPCall(script)
#enddef

def import_agentcall(imports, script):
    '''Like `agentcall`, but include a specification of values to be imported into
    the script's scope.

    Imports are a feature that can be implemented by subclasses; in `BaseRPC`
    they are ignored.
    '''
    return AgentRPCall(script, imports=imports)
#enddef

def hostcall(func):
    '''Decorator for defining functions running on the host that can be called
    from the agent.

    Only meant to be used within a `BaseRPC` subclass definition.

    To call the function, use the `kahlo.hostcall` object from the agent: call
    function `foo` as `kahlo.hostcall.foo(arg, ...)`. Note that the function
    is asynchronous.

    '''
    return HostRPCall(func)
#enddef

# RPC metaclass that builds the RPC class from RPCall objects, created via
 # hostcall and agentcall helpers.
class RPCMeta(type):

    def _merge_imports(imports, new):
        for (impname, impspec) in new.items():
            if impname in imports:
                if impspec != imports[impname]:
                    raise ImportConflictExn(
                        "Conflicting imports for symbol {}: {!r}".format(
                            impname,
                            (impspec, imports[impname])))
                #endif
            else:
                imports[impname] = impspec
            #endif
        #endfor        
        return imports
    #enddef

    def __new__(meta, name, bases, dct):
        agent_calls_info = {}
        host_calls_info = {}
        imports_info = {}
        newdct = {}
        for (n, v) in dct.items():
            if not isinstance(v, RPCall):
                newdct[n] = v
                continue
            #endif
            if isinstance(v, AgentRPCall):
                agent_calls_info[n] = {
                    "script" : v.script,
                    "func" : v.wrapfunc,
                }
                if v.imports != None:
                    meta._merge_imports(imports_info, v.imports)
                #endif
            elif isinstance(v, HostRPCall):
                host_calls_info[n] = {
                    "func" : v.func
                }
                newdct[n] = v.func
            #endif
        #endfor

        newdct["_agent_calls_info"] = agent_calls_info
        newdct["_host_calls_info"] = host_calls_info
        newdct["_agent_imports_info"] = imports_info

        return super().__new__(meta, name, bases, newdct)
        
    #enddef
    
#endclass

# Used for BaseRPC.agentcall.
class AgentCaller(object):
    def __init__(self, rpc): self.__rpc = rpc
    def __getattr__(self, name): return self.__rpc.get_agentcall(name)
#endclass

class BaseRPC(scribe.Scribe, metaclass=RPCMeta):
    '''Bidirectional RPC base class.

    This class provides support for implementing bidirectional RPC between
    frida hosts and agents. Subclasses can define functions running on the
    host and called from the agent, and vice versa.

    Use the `hostcall` and `remotecall` helper functions to easily define RPC
    functions. Any field or method not tagged using `hostcall` or `remotecall`
    will be treated as a regular, un-exposed function.
    '''
    
    _SCRIPT = '''//JS
    var func = (function () {

        let rpcman = {
        
            rpcid_counter: 1,
            new_rpcid() { return this.rpcid_counter++; },

            contexts: {},

            create_context() {
                const rpcid = this.new_rpcid();
                var ctx = { rpcid: rpcid };
                this.contexts[rpcid] = ctx;
                return ctx;
            },

            // Make a call to the host, and returns a promise that resolve to the
            // value returned by the host.
            make_host_call(procname, args) {
                const ctx = this.create_context();
                send({
                    subsystem : "rpc",
                    rpctype : "host_call",
                    rpcid : ctx.rpcid,
                    procname : procname,
                    args : args
                });
                return new Promise(resolve => { ctx.resolver = resolve });
            },

            // Called when the host call has returned with a result.
            complete_host_call(rpcid, result) {
                this.contexts[rpcid].resolver(result);
            },

            // Sends a result back to the host.
            send_agent_result(rpcid, result) {
                send({
                    subsystem: "rpc",
                    rpctype: "agent_result",
                    rpcid: rpcid,
                    result: result
                });
            },

        };

        // Add hostcalls to kahlo namespace.
        Object.assign(kahlo, {

            hostcall : Object.fromEntries(
                kahlo.env.hostcalls.map(k => [
                    k,
                    async function () {
                        return await rpcman.make_host_call(k, Array.from(arguments));
                    }
                ])),

        });

        // Set up agent exports.
        rpc.exports = Object.fromEntries(
            Object.keys(kahlo.env.agentcalls).map(k => [
                k,
                function (rpcid, args) {
                    var rv = kahlo.env.agentcalls[k].apply(null, args);
                    if (rv == undefined) { rv = null; }
                    if (rv instanceof Promise) {
                        rv.then(v => {
                            rpcman.send_agent_result(rpcid, v);
                        });
                    } else {
                        rpcman.send_agent_result(rpcid, rv);
                    }
                }
            ]));

        // Incoming message handler.
        kahlo.registerSubsystem("rpc", function (msg) {
            // console.log("Got RPC message: " + JSON.stringify(msg));

            const rpcid = msg["rpcid"]
            const rpctype = msg["rpctype"]

            switch (rpctype) {
            case "host_result":
                rpcman.complete_host_call(rpcid, msg["result"]);
                break;
            default:
                console.log("WARNING: message from host with unknown type: " + JSON.stringify(msg));
                
            }

        })
                

    });
    func();
    '''

    def _gather_host_calls_infos(self, cls, dct):
        if issubclass(cls, BaseRPC) and not cls == BaseRPC:
            for c in cls.__bases__:
                self._gather_host_calls_infos(c, dct)
            #endfor
            dct.update(cls._host_calls_info)
        #endif
        return dct
    #enddef

    def _gather_agent_calls_infos(self, cls, dct):
        if issubclass(cls, BaseRPC) and not cls == BaseRPC:
            for c in cls.__bases__:
                self._gather_agent_calls_infos(c, dct)
            #endfor
            dct.update(cls._agent_calls_info)
        #endif
        return dct
    #enddef
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.register_subsystem("rpc", self.on_rpc_message)

        # Note: This sets the instance's *_info fields to the gathered fields
        # from the class and all superclasses.
        self._host_calls_info = self._gather_host_calls_infos(self.__class__, {})
        self._agent_calls_info = self._gather_agent_calls_infos(self.__class__, {})
        
        agentcalls = "{\n" + \
            ",\n".join(["{} : ({})".format(frida.core._to_camel_case(n), info["script"])
                        for (n, info)
                        in self._agent_calls_info.items()]) + \
                        "\n}"
        self.set_script_env("agentcalls", agentcalls, is_raw=True)
    
        self.set_script_env("hostcalls", list(self._host_calls_info.keys()))

        self.ctxman = ContextManager()

        self._agentcaller = AgentCaller(self)
        
    #enddef
   
    def on_rpc_message(self, payload, data):
        # print("Got an RPC message: {!r}, {!r}".format(payload, data))
        rpcid = payload["rpcid"]
        rpctype = payload["rpctype"]

        if rpctype == "host_call":
            procname = payload["procname"]
            args = payload["args"]
            if procname in self._host_calls_info:
                func = self._host_calls_info[procname]["func"]
                rv = func(self, *args)
                # Post result of call back to agent.
                self.post_subsystem_msg("rpc", {
                    "rpcid" : payload["rpcid"],
                    "rpctype" : "host_result",
                    "result" : rv
                })
            else:
                print("WARNING: Unknown host import {!r}, ignoring.".format(procname))
            #endif
        elif rpctype == "agent_result":
            result = payload["result"] if "result" in payload else None
            self.ctxman.set_context_result(rpcid, result)
        else:
            print("WARNING: Unknown RPC type {!r}, ignoring.".format(rpctype))
        #endif
        
    #enddef

    def get_agentcall(self, name):
        if name in self._agent_calls_info:
            wrapfunc = self._agent_calls_info[name]["func"]
            agentcall = getattr(self._script.exports, name)
            async def _do_agentcall(*args):
                ctx = self.ctxman.create_context()
                agentcall(ctx.rpcid, args)
                result = await ctx.completed()
                self.ctxman.clear_context(ctx)
                return result
            #enddef
            if wrapfunc == None:
                # No wrapping function, so directly return the agentcall
                # function.
                return _do_agentcall
            else:
                # Call wrapping function, passing it the agentcall function to
                # be called from within.
                async def _do_wrapped_agentcall(*args, **kwargs):
                    return await wrapfunc(self, _do_agentcall, *args, **kwargs)
                #enddef
                return _do_wrapped_agentcall
            #endif
        else:
            raise AttributeError("No agentcall named '{}' found.".format(name))
        #endif
    #enddef

    @property
    def agentcall(self): return self._agentcaller
    
#endclass
    
