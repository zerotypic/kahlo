# -XXX*- mode: poly-pyjs -*-
#
# velcro : Add hooks to functions
#

import asyncio

from . import rpc
from . import signature
from . import android

class Exn(Exception): pass
class ExistingHookExn(Exn): pass
class TracerExn(Exn): pass

class HookTarget(object):
    '''A target function or method that can be hooked.'''

    def get_id(self): raise NotImplemented
    
#endclass

class JavaHookTarget(HookTarget):
    def __init__(self, sig):
        assert isinstance(sig, android.MethodSignature)
        self.sig = sig
    #enddef

    def get_id(self): return "java!!" + self.sig.to_logical().to_disp()

#endclass

class NativeHookTarget(HookTarget):
    def __init__(self, libname, funcname):
        self.libname = libname
        self.funcname = funcname
    #enddef

    def get_id(self): return "native!!{}:{}".format(self.libname, self.funcname)
    
#endclass

class HookContext(object):
    '''A pending or running instance of a hook handler.

    Each time a hook is triggered, a new handler coroutine will be executed,
    with a HookContext object as the associated context.
    '''
    
    def __init__(self, parent, tid):
        self.parent = parent
        self.tid = tid
        self.coro = self.parent.func(self)
        self.args = None
        self.retval = None
        self.return_ev = asyncio.Event(loop=self.parent._event_loop)
        self.is_done = False
    #enddef

    @property
    def target(self): return self.parent.target

    def _cleanup_future(self, fut):
        # print("_cleanup_future called for future: {!r}".format(fut))
        self.is_done = True
        if not fut.cancelled():
            exn = fut.exception()
            if exn != None:
                import traceback
                traceback.print_exception(None, exn, exn.__traceback__)
            #endif
        #endif
        self.parent._cleanup_context(self)
    #enddef
    
    def run(self, args):
        # print("HookContext.run: args={!r}, coro={!r}".format(args, self.coro))
        self.args = args
        self.coro_future = asyncio.run_coroutine_threadsafe(self.coro, self.parent._event_loop)
        self.coro_future.add_done_callback(self._cleanup_future)
        # print("\tHookContext.run completed.")
    #enddef
    
    async def complete(self):
        await self.return_ev.wait()
        return self.retval
    #enddef

    def set_return_value(self, retval):
        self.retval = retval
        self.parent._event_loop.call_soon_threadsafe(self.return_ev.set)
    #enddef
    
#enddef

class Hook(object):
    '''A hook onto a specific Java method or C function.

    The method or function is determined by the passed in signature. When the
    hook is triggered, the coroutine returned by the passed in function is
    run.
    '''

    # Note: If func is None, then no context is created when the hook is triggered.
    def __init__(self, manager, target, func, inline_js=None):
        self.manager = manager

        assert isinstance(target, HookTarget)
        self.target = target
        self.func = func
        self.inline_js = inline_js
        self.contexts = {}
        self.returned_contexts = []
    #enddef

    def trigger_start(self, tid, args):
        if self.func == None: return

        if not tid in self.contexts: self.contexts[tid] = []
        thd_contexts = self.contexts[tid]
        ctx = HookContext(self, tid)
        ctx.run(args)
        thd_contexts.append(ctx)       
    #enddef

    def trigger_return(self, tid, retval):
        if self.func == None: return

        ctx = self.contexts[tid].pop()
        ctx.set_return_value(retval)
        if not ctx.is_done:
            self.returned_contexts.append(ctx)
        #endif
    #enddef

    def _cleanup_context(self, ctx):
        if ctx in self.returned_contexts:
            self.returned_contexts.remove(ctx)
        #endif
    #enddef
    
    @property
    def _event_loop(self):
        return self.manager._event_loop
    #enddef
    
#endclass


class Velcro(rpc.BaseRPC):
    _SCRIPT = r'''//JS
    // Initialization
    //Java.perform(function () {
    //Java.deoptimizeEverything();
    //});

    function LOG(s) { console.log(s); }

    // XXX: Should this be done here, or elsewhere?
    const _special_name_map = {
        "<init>" : "$init"   ,
        "<clinit>" : "$clinit" 
    }
    function ensure_frida_name(s) {
        if (_special_name_map[s] != undefined)
            return _special_name_map[s]
        else
            return s
    }

    function _do_wrap_obj(obj, use_static) {
        const clsname = obj.$n;
        const info = kahlo.velcro.imported_class_info[clsname];
        if (info == undefined) {
            LOG(`Error: could not wrap class or instance of ${clsname} as class is not imported.`);
        }
        // LOG(`Wrapping object ${clsname}, logical sig = ${info["logical_sig"]}`);
        var wrapper = {
            "$o" : obj
        };
        for (const [lsig, meth_info] of Object.entries(info["methods"])) {
            // Only use static methods if use_static is true, else only use instance methods
            if (meth_info["static"] != use_static) continue;

            const rtname = ensure_frida_name(meth_info["runtime_name"]);
            // LOG(`\tWrapping method: ${lsig}, rtname=${rtname}`);
            
            // The function to be wrapped
            let func = obj[rtname];
            
            // Sometimes, there might be no method with name `rtname` in the
            // object, possibly because the spec is not accurate. Just ignore
            // if so.
            if (func != undefined) {

                if (func.overloads != undefined) {
                    func = func.overload.apply(func, meth_info["frida_params"])
                }
                
                wrapper[meth_info["logical_name"]] = function () {
                    // LOG(`Calling wrapper of ${meth_info["logical_name"]}.`);
                    // LOG(`\tfunc.methodName = ${func.methodName}`);
                    // LOG("\targuments = " + JSON.stringify(arguments));
                    return func.apply(obj, arguments);
                }
            }
        }
        
        for (const [lsig, field_info] of Object.entries(info["fields"])) {
            if (field_info["static"] != use_static) continue;
            // LOG(`\tWrapping property: ${lsig}`);
            // LOG(`\t\tRuntime name: ${field_info["runtime_name"]}`);
            Object.defineProperty(
                wrapper,
                field_info["logical_name"],
                { get() { return obj[field_info["runtime_name"]] }}
            );
        }
        return wrapper;
    }
        
    Object.assign(kahlo, {

        // Create velcro global namespace.
        velcro : {

            imported_class_info : {},
            import_name_map : {},

            register_imported_class : async function(clsname, cls, impname) {
                LOG(`Registering class as import ${impname}: name ${clsname}, obj: ${cls}`);
                let details = await kahlo.hostcall.get_sig_details(clsname, true, true);
                if (details != null) {
                    const cls_logical_sig = await kahlo.hostcall.sig_get_logical(clsname, true);
                    Object.assign(details, {
                        obj : cls,
                        "logical_sig" : cls_logical_sig,
                        "logical_sig_disp" : await kahlo.hostcall.sig_format_to_disp(cls_logical_sig),
                    });
                    for (const [msig, minfo] of Object.entries(details["methods"])) {
                        minfo["frida_params"] = await kahlo.hostcall.convert_meth_params(minfo["params"]);
                        minfo["frida_retty"] = (await kahlo.hostcall.convert_meth_params([minfo["retty"]]))[0];
                    }
                    this.imported_class_info[clsname] = details;
                    this.import_name_map[impname] = clsname;
                } else {
                    LOG(`Note: class ${clsname} does not have detailed info.`);
                }
            },

            wrap_instance : function(inst) {
                return _do_wrap_obj(inst, false);
            },

            wrap_class : function(cls) {
                return _do_wrap_obj(cls, true);
            },

            get_method_lookup_function : function(cls) {
                const clsname = cls.$n;
                const info = kahlo.velcro.imported_class_info[clsname];
                return function (meth_lsig) {
                    const meth_full_sig = info["logical_sig_disp"] + "->" + meth_lsig;
                    return info["methods"][meth_full_sig];
                };                
            },

            create_class_implementation : function(name, intf, methods) {

                const intf_info = kahlo.velcro.imported_class_info[intf.$n];
                const method_lookup = kahlo.velcro.get_method_lookup_function(intf);

                const build_methods = {};              
                Object.entries(methods).forEach(function ([meth_lsig, meth_impl]) {
                    const meth_info = method_lookup(meth_lsig);
                    const meth_name = meth_info["runtime_name"]
                    if (build_methods[meth_name] == null) {
                        build_methods[meth_name] = []
                    }
                    build_methods[meth_name].push([meth_impl, meth_info])
                });
                
                const rtmethods = Object.fromEntries(
                    Object.entries(build_methods).map(function ([meth_name, impl_infos]) {
                        if (impl_infos.length == 1) {
                            return [meth_name, impl_infos[0][0]];
                        } else {
                            // XXX: CODE HERE HASN'T BEEN TESTED YET!
                            return [meth_name,
                                    impl_infos.map(function ([meth_impl, meth_info]) {
                                        return {
                                            returnType : meth_info["frida_retty"],
                                            argumentTypes : meth_info["frida_params"],
                                            implementation : meth_impl
                                        }
                                    })];
                        }
                    })
                );

                return Java.registerClass({
                    name : name,
                    implements : [intf],
                    methods : rtmethods
                });                
            }

            
            
        }
        
    });
    
    '''
    _AGENT_IMPORTS = None
    
    def __init__(self, scm, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._scheme = scm
        self._hooks = {}
        self._event_loop = asyncio.get_event_loop()

        # Set up imports

        imports = self._AGENT_IMPORTS if self._AGENT_IMPORTS != None else {}

        type(type(self))._merge_imports(imports, self._agent_imports_info)
        
        imports_script = "\n".join((
            '''//JS
            const {impname} = Java.use("{rtsig}");
            kahlo.velcro.register_imported_class("{rtsig}", {impname}, "{impname}");
            '''.format(
                impname = impname,
                rtsig = self._scheme.from_disp(impspec).to_runtime().to_frida()
            )
            for (impname, impspec)
            in imports.items()))
        
        # We use the postamble in order to allow us to add the imported class
        # names to the scope of all functions and hooks.
        self.set_script_postamble(imports_script)
        
    #enddef
    
    async def add_java_hook(self, sig, func, inline_js=None):
        sigstr = self._scheme.to_runtime(sig).to_disp()
        target = JavaHookTarget(sig)
        target_id = target.get_id()
        assert not target_id in self._hooks
        self._hooks[target_id] = Hook(self, target, func, inline_js=inline_js)
        await self.agentcall.do_add_java_hook(sigstr, target_id, inline_js)
    #enddef

    async def add_inline_java_hook(self, sig, inline_js):
        await self.add_java_hook(sig, None, inline_js=inline_js)
    #enddef
    
    do_add_java_hook = rpc.agentcall('''//JS
    async function(sig, target_id, inline_js) {
        //function LOG(s) { console.log(s); }
        
        // var sig_info = await kahlo.hostcall.get_android_siginfo(sig, true);
        // var clsname = sig_info["clsname"]
        // var methname = sig_info["methname"]
        // var paramtys = sig_info["paramtys"]

        const sig_info = await kahlo.hostcall.parse_sig(sig);
        const clsname = sig_info["clsty"]
        const methname = sig_info["name"]
        const paramtys = sig_info["params"]
        
        // LOG("addHook:")
        // LOG("\tclsname = " + clsname)
        // LOG("\tmethname = " + methname)
        // LOG("\tparamtys = " + JSON.stringify(paramtys))

        var inline_func = null;
        if (inline_js != null) {
            inline_func = eval("(" + inline_js + ")");
        }
        
        Java.perform(function () {
            var cls = Java.use(clsname)
            // LOG("cls = " + cls)
            var basemeth = cls[methname]
            // LOG("basemeth = " + basemeth)
            var meth = basemeth.overload.apply(basemeth, paramtys)
            meth.implementation = function () {
                const Thread = Java.use("java.lang.Thread");
                var tid = parseInt(Thread.currentThread().getId());
                // Note: This is an async function, so it returns a
                // Promise. Since we're not in an async function, we can't
                // call await, so we just ignore the Promise and continue on.
                kahlo.hostcall.notify_call(
                    tid,
                    target_id,
                    [this.toString()].concat(
                        Array.from(arguments).map(a => a ? a.toString() : "null")
                    )
                );

                var rv = null;
                if (inline_func != null) {
                    // The inline JS function is responsible for calling the hooked method
                    // if required.
                    rv = inline_func(this, meth, arguments);
                } else {
                    rv = meth.apply(this, arguments);
                }

                // Note: Same issue as notify_call() regarding async.
                kahlo.hostcall.notify_return(
                    tid,
                    target_id,
                    rv ? rv.toString() : null
                );
                return rv;
            };
            LOG("Hooked method: " + sig);
        });
    }
    ''')

    add_native_hook = rpc.agentcall('''//JS
    async function(libname, funcname, target_id, inline_js) {
        var target_func = Module.findExportByName(libname, funcname);

        // XXX: Think about how to change it so we're using an async function
        // here instead of a callback object. Will make the API more consistent.
        var inline_obj = null;
        if (inline_js != null) {
            inline_obj = eval("(" + inline_js + ")");
        }

        Interceptor.attach(target_func, {
            onEnter: async function(args) {
                const tid = Process.getCurrentThreadId()

                // Build args list
                const copied_args = Array.from(
                    {length: 10},
                    (_, i) => parseInt(args[i])
                )

                if (inline_obj != null) {
                    inline_obj.onEnter(args);
                }

                // Note: once we call await, args appears to become invalid.
                // XXX TODO: Try to figure out why.
                await kahlo.hostcall.notify_call(
                    tid,
                    target_id,
                    copied_args
                );

            },
            onLeave: async function (retval) {
                const tid = Process.getCurrentThreadId()

                if (inline_obj != null) {
                    inline_obj.onLeave(retval);
                }

                await kahlo.hostcall.notify_return(
                    tid,
                    target_id,
                    retval ? retval.toString() : null
                );
            }
        });
    }    
    ''')
    @add_native_hook.wrapper
    async def add_native_hook(self, makecall, libname, funcname, func, inline_js=None):
        target = NativeHookTarget(libname, funcname)
        target_id = target.get_id()
        assert not target_id in self._hooks
        self._hooks[target_id] = Hook(self, target, func, inline_js=inline_js)
        await makecall(libname, funcname, target_id, inline_js)
        #enddef

    async def add_inline_native_hook(self, libname, funcname, inline_js):
        await self.agentcall.add_native_hook(libname, funcname, None, inline_js=inline_js)
    #enddef

    
    @rpc.hostcall
    def notify_call(self, tid, target_id, args):
        # print("Hit notify_call: tid={!r}, target_id={!r}, args={!r}".format(tid, target_id, args))
        hook = self._hooks[target_id]
        # print("\thook = {!r}".format(hook))
        hook.trigger_start(tid, args)
    #enddef

    @rpc.hostcall
    def notify_return(self, tid, target_id, rv):
        # print("Hit notify_return: tid={!r}, target_id={!r}, rv={!r}".format(tid, target_id, rv))
        hook = self._hooks[target_id]
        # print("\thook = {!r}".format(hook))
        hook.trigger_return(tid, rv)
    #enddef

    # XXX: This should be removed as it can be replaced by parse_sig().
    @rpc.hostcall
    def get_android_siginfo(self, sigstr, use_runtime=False):
        sig = self._scheme.from_disp(sigstr)
        if use_runtime: sig = sig.to_runtime()
        assert isinstance(sig, android.MethodSignature)
        rv = {
            "clsname" : sig.clsty.to_frida(),
            "methname" : sig.name,
            "paramtys" : [p.to_frida() for p in sig.params]
        }
        return rv
    #enddef

    def _get_sig(self, sigstr, force_logical, is_frida_format):
        sig = (self._scheme.from_frida if is_frida_format else self._scheme.from_disp)(sigstr)
        return sig.to_logical() if force_logical else sig
    #enddef
    
    @rpc.hostcall
    def get_sig_details(self, sigstr, is_runtime_name=False, is_frida_format=False):
        sig = self._get_sig(sigstr, is_runtime_name, is_frida_format)
        return sig.get_details() if sig.has_details() else None
    #enddef

    @rpc.hostcall
    def parse_sig(self, sigstr, is_frida_format=False):
        sig = self._get_sig(sigstr, False, is_frida_format)
        return sig.to_json()
    #enddef
    
    @rpc.hostcall
    def sig_get_logical(self, sigstr, is_frida_format=False):
        sig = self._get_sig(sigstr, True, is_frida_format)
        return sig.to_disp() if not is_frida_format else sig.to_frida()
    #enddef

    @rpc.hostcall
    def sig_get_runtime(self, sigstr, is_frida_format=False):
        sig = self._get_sig(sigstr, False, is_frida_format).to_runtime()
        return sig.to_disp() if not is_frida_format else sig.to_frida()
    #enddef

    @rpc.hostcall
    def sig_format_to_frida(self, sigstr):
        return self._get_sig(sigstr, False, False).to_frida()
    #enddef

    @rpc.hostcall
    def sig_format_to_disp(self, sigstr):
        return self._get_sig(sigstr, False, True).to_disp()
    #enddef

    @rpc.hostcall
    def convert_meth_params(self, params):
        # XXX: Refactor this to not depend on jebandroid
        from .jebandroid import JebTypeName
        def trans_if_clsty(ty):
            if isinstance(ty, android.ClsType):
                return self._scheme.to_runtime(android.ClassSignature(ty)).clsty
            else:
                return ty
            #endif
        #enddef
        return [trans_if_clsty(JebTypeName.parseString(p)[0]).to_frida() for p in params]
    #enddef

    
    get_classes = rpc.agentcall('''//JS
    function() {
        return new Promise((resolve, reject) => {
            Java.perform(function() {
                resolve(Java.enumerateLoadedClassesSync());
            });
        });
    }
    ''')
    @get_classes.wrapper
    async def get_classes(self, makecall):
        result = await makecall()
        return [self._scheme.from_frida(c).to_logical().to_disp() for c in result]
    #enddef

    
    get_class_methods = rpc.agentcall('''//JS
    function(clsname) {
        return new Promise((resolve, reject) => {
            Java.perform(function() {
                LOG("Enumerating methods in class " + clsname);
                const groups = Java.enumerateMethods(clsname + "!*/s");
                if (groups.length == 0) {
                    LOG("groups.length == 0")
                    resolve([])
                } else {
                    resolve(groups[0].classes[0].methods)
                }
            });
        });
    }
    ''')
    @get_class_methods.wrapper
    async def get_class_methods(self, makecall, clsname):
        frida_clsname = self._scheme.from_disp(clsname).to_runtime().to_frida()
        result = await makecall(frida_clsname)
        return [
            self._scheme
            .from_frida("{}.{}".format(frida_clsname, r))
            .to_logical()
            for r in result
        ]
    #enddef

    read_cstring = rpc.agentcall('''//JS
    function(addr) {
        return ptr(addr).readCString()
    }
    ''')

    read_pointer = rpc.agentcall('''//JS
    function(addr) {
        return ptr(addr).readPointer().toString()
    }
    ''')
    @read_pointer.wrapper
    async def read_pointer(self, makecall, addr):
        return int(await makecall(addr))
    #enddef
    
    agent_exec = rpc.agentcall('''//JS
    function(codestr) {
        var func = eval("(function() {" + codestr + "})");
        return func()
    }    
    ''')

    agent_exec_async = rpc.agentcall('''//JS
    async function(codestr) {
        var func = eval("(async function() {" + codestr + "})");
        return await func()
    }    
    ''')

    
    do_import_agentcall = rpc.agentcall('''//JS
    function(imports, func_js) {
        var ctx = Object.fromEntries(
            Object.entries(imports),
            ([import_name, class_name]) => [import_name, Java.use(class_name)]
        );
        LOG("ctx = " + ctx);
        var func = eval("(" + func_js + ")").bind(ctx);
        func();
    }
    ''')

#endclass

class Tracer(object):
    
    def __init__(self, velcro):
        self.velcro = velcro
        self.threadinfos = {}
    #enddef

    def init_threadinfo(self, tid):
        if tid in self.threadinfos:
            raise TracerExn("Already have threadinfo for tid {:d}".format(td))
        #endif
        self.threadinfos[tid] = {
            "depth" : 0,
        }
    #enddef

    def push_thread(self, tid):
        if not tid in self.threadinfos:
            self.init_threadinfo(tid)
        #enddif
        self.threadinfos[tid]["depth"] += 1
    #enddef

    def pop_thread(self, tid):
        if not tid in self.threadinfos:
            self.init_threadinfo(tid)
        #enddif
        if self.threadinfos[tid]["depth"] > 0:
            self.threadinfos[tid]["depth"] -= 1
        #endif
    #enddef
    
    def get_logger_for_thread(self, tid):
        if not tid in self.threadinfos:
            self.init_threadinfo(tid)
        #endif
        info = self.threadinfos[tid]
        depth = info["depth"]
        def _log(msg):
            print("[{tid:02d}]\t{indent}{msg}".format(
                tid = tid,
                indent = "   " * depth,
                msg = msg))
        #enddef
        return _log
    #enddef

    def _format_arg(self, arg, maxlen=400):
        if type(arg) != str: arg = repr(arg)
        return arg[:maxlen - 2] + ".." if len(arg) > maxlen else arg
    #enddef
    
    async def _trace_function_hook(self, ctx):
        LOG = self.get_logger_for_thread(ctx.tid)

        if isinstance(ctx.target, JavaHookTarget):       
            nice_sig = ctx.target.sig.to_logical().to_disp()
            LOG("\U0001f806 {}:".format(nice_sig))
        elif isinstance(ctx.target, NativeHookTarget):
            LOG("\U0001f806 {}:{}".format(ctx.target.libname, ctx.target.funcname))
        else:
            LOG("\U0001f806 ???{}".format(repr(ctx.target)))
        #endif

        argstr = ", ".join([self._format_arg(a) for a in ctx.args])
        LOG(" ({})".format(argstr))

        self.push_thread(ctx.tid)
        await ctx.complete()
        self.pop_thread(ctx.tid)

        LOG(" \U0001f804 {}".format(self._format_arg(ctx.retval)))
        
    #enddef    

    async def trace_sig(self, sig):
        await self.velcro.add_java_hook(sig, self._trace_function_hook)
    #enddef

#endclass
