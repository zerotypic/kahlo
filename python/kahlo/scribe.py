#
# scribe : Script-carrying objects
#

import json
import string
import frida

__all__ = ("Scribe",)

class Exn(Exception): pass
class BindExn(Exn): pass

class Scribe(object):
    '''High-level scripting object for frida.

    A `Scribe` is an object that holds a JavsScript script, which can be bound
    to a frida `Session`. To use, create a subclass of `Scribe`, and write the
    script in the class's `_SCRIPT` field. The `Scribe` base class will
    concatenate all scripts found in its subclasses to form the final script
    that is bound to the session.

    The `Scribe` object also manages messages sent between the host and the
    agent. A subclass can register a subsystem using
    `Scribe.register_subsystem` on the host, and `kahlo.registerSubsystem` on
    the agent, in order to receive messages from the subsystem accordingly.
    '''
    
    _SCRIPT = '''//JS
    var kahlo = {
        env : $SCRIPT_ENV,
        _subsystemMap : {},
    };

    kahlo.registerSubsystem = function (name, handler) {
        kahlo._subsystemMap[name] = handler;
    }
    
    kahlo.recvHandler = function (msg) {
        var subsystem = msg["subsystem"];
        if (subsystem != undefined) {
            var handler = kahlo._subsystemMap[subsystem];
            if (handler != undefined) {
                handler(msg);
            } else {
                console.log("WARNING: Recieved message for unregistered subsystem " + subsystem);
            }
        } else {
            console.log("WARNING: Received message with missing subsystem field: " +
                        JSON.stringify(msg));
        }
        recv("kahlo", kahlo.recvHandler);
    }   
    recv("kahlo", kahlo.recvHandler);

    
    '''
   
    def __init__(self, session):
        self._session = session
        self._script = None
        # Holds environment variables to pass into the script via
        # kahlo.env. Dict where key is the name of the environment variable,
        # and value is a string that will be used as the raw Javascript
        # expression assigned to the variable.
        self._script_env = {}
        self._subsystem_map = {}

        # Additional per-object code that can be added to the script. If used,
        # must be set before the script is bound.
        self._script_postamble = None
        
        # Auxillary scripts that can be added if required.
        self._aux_scripts = []
    #enddef


    def set_script_env(self, name, value, is_raw=False):
        if not is_raw:
            try:
                value = json.dumps(value)
            except TypeError as e:
                raise BindExn("Script environment value cannot be converted to JSON: {!r}".format(e))
            #endtry
        #endif
        self._script_env[name] = value
    #enddef
    

    def set_script_postamble(self, jscode):
        self._script_postamble = jscode
    #enddef

    def bind(self):

        # Build string representation of environment variables.
        script_env_str = "{" + \
            ",\n".join(["{} : {}".format(k, v) for (k, v) in self._script_env.items()]) + \
            "}"

        # Build the final script to be injected.
        allbases = []
        def getbases(cls):
            if cls in allbases: return
            if cls == Scribe: return
            allbases.append(cls)
            for c in cls.__bases__: getbases(c)
        #enddef
        getbases(self.__class__)
        allbases.reverse()

        basescript = string.Template(Scribe._SCRIPT).substitute(
            SCRIPT_ENV = script_env_str
        )
        
        fullscript = "\n".join([basescript] + [c._SCRIPT for c in allbases])

        if self._script_postamble:
            fullscript += self._script_postamble
        #endif
        
        self._script_str = fullscript

        wrapped_fullscript = "Java.perform(() => {{ {} }});".format(fullscript)

        try:
            self._script = self._session.create_script(wrapped_fullscript)
        except frida.InvalidArgumentError as e:
            # Try to parse the exception and print out lines with errors.
            import re
            m = re.compile("^script\(line (\d+)\)").match(e.args[0])
            if m != None:
                print("Error running script: {}".format(e.args[0]), end="\n\t")
                line = int(m[1]) - 1
                print("\n\t".join(wrapped_fullscript.splitlines()[max(line-1, 0):line+2]))
                print("="*80)
                print("".join(["{}\t{}\n".format(i+1, l) for (i, l) in enumerate(wrapped_fullscript.splitlines())]))
            #endif
            raise BindExn(e.args[0]) from e
        #endtry                
        
        self._script.on("message", self._on_message)
        self._script.load()

    #enddef

    def add_aux_script(self, jscode):
        script = self._session.create_script(jscode)
        script.load()
        self._aux_scripts.append(script)
    #enddef
    
    def register_subsystem(self, subsys, handler):
        self._subsystem_map[subsys] = handler
    #enddef

    def post_subsystem_msg(self, subsystem, msg):
        msg["type"] = "kahlo"
        msg["subsystem"] = subsystem
        self._script.post(msg)
    #enddef
    
    def _on_message(self, message, data):
        if message["type"] == "error":
            self.on_error_message(message, data)
        elif message["type"] == "send":
            payload = message["payload"]
            
            if "subsystem" in payload:
                subsys = payload["subsystem"]
                if subsys in self._subsystem_map:
                    self._subsystem_map[subsys](payload, data)
                else:
                    print("WARN: Unknown subsystem {!r}.".format(subsys))
                    self.on_other_message(message, data)
                #endif
            else:
                self.on_other_message(message, data)
        else:
            self.on_other_message(message, data)
        #endif      

    #enddef
    
    # Message handler for other kinds of messages.
    def on_other_message(self, message, data):
        print("Got message: {!r}, {!r}".format(message, data))
    #enddef

    # Message handler for error messages.
    def on_error_message(self, message, data):
        if "lineNumber" in message and "columnNumber" in message:
            print("ERROR at line {} column {}:".format(message["lineNumber"], message["columnNumber"]))
        else:
            print("ERROR:")
        #endif
        if "stack" in message:
            print(message["stack"])
        else:
            print(repr(message))
        #endif
    #enddef

#endclass
