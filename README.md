kahlo : Higher-level Python interface for frida
===============================================

```python
>>> import frida
>>> import kahlo

# The Scribe class has an associated script.
>>> class TestScribe(kahlo.Scribe):
...    _SCRIPT = '''console.log("hello world");'''

# Create a frida session.
>>> session = frida.get_local_device().attach("nano")

# Create a Scribe subclass associated with the session.
>>> test = TestScribe(session)

# Bind the Scribe object to the session, causing script to be run on the
# agent.
>>> test.bind()
hello world

# Bidirectional async RPC
>>> class TestRPC(kahlo.rpc.BaseRPC):
...    @kahlo.rpc.hostcall
...    def host_hello(self, name):
...        print("Hello {}".format(name))
...        return "nice to meet you"
...
...    agent_call_host = kahlo.rpc.agentcall('''
...       async function (name) {
...          var rv = await kahlo.hostcall.host_hello("agent " + name)
...          console.log("host said " + rv);
...          return 42
...       }
...    ''')
>>> rpc = TestRPC(session)
>>> rpc.bind()
>>> await rpc.agentcall.agent_call_host("foo")
Hello agent foo
host said nice to meet you
42
```

## Design Rationale

The main rationale behind kahlo is to facilitate host-centric use of
frida. Most tools and scripts built on frida tend to be more agent-centric;
they are mostly Javascript that runs within the agent (at least based on what
I've seen out there). This is usually fine, and an efficient way of doing
things. But there are situations where this is a problem, usually because
there is some analysis that you want to do, which cannot be done on the
agent, especially if your target is an embedded device.

For example:

* You need to access some data over the network/Internet, but your target device cannot
  be connected to a network for whatever reason.

* Your analysis requires coordination over multiple devices, so you need to
  consolidate the logic within a central management system on the host.

* You need to process something beyond the capabilities of the target's CPU or
  memory.
  
In my specific use case, I needed something that let me interoperate with JEB
(https://www.pnfsoftware.com/jeb/) and other static analysis tools built on
top of that, running on the host.

As such, kahlo is meant for building tools where the code running on the agent
is usually minimal (and hence suitable for inlining within Python code), just
gathering data and passing it to the host to process.

## Features

Here are some features available in kahlo so far.

### Composable Inline Scripts

The `Scribe` class lets you specify some Javascript code you want to run in
the agent. Subclasses of the class will append their script to the superclass
script.

```python
class TestScribe(kahlo.Scribe):
    _SCRIPT = '''
    console.log("Hello world");
    '''

class AnotherScribe(TestScribe):
    _SCRIPT = '''
    console.log("This gets run after the superclass script. Bye!");
    '''
```

### Bi-directional RPC

Builds upon frida's RPC framework to provide asynchronous RPC between host and
agent and vice versa.

```python
class TestRPC(kahlo.rpc.BaseRPC):

    agent_callhost = kahlo.rpc.agentcall('''
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
    
    async def call_into_agent(self, foo, bar):
        rv = await self.agentcall.agent_callhost(foo, bar)
        print("Got rv = {!r}".format(rv))
```

### Class and Function Signature Management

A signature is a unique identifier for a class or function/method. A signature
can be formatted in several ways for display, and can also be converted
between logical and runtime versions.

The main purpose of the signature module is to provide support for cases where
the runtime signatures (aka symbols) associated with a class or function are
different from the signatures the user would like to work with. For example,
an obfuscated/minified Android application would have class and method
signatures that differ from the original, unobfuscated signatures.

Allowing signatures to be displayed in different formats also allows kahlo to
work better with tools that use alternative formats. For example, the provided
`jebandroid` module allows for interoperability with the format used by the
JEB Decompiler.

```python
>>> scm.from_disp("Lcom/foo/bar;-><clinit>()V").to_frida()
'com.foo.bar.$clinit(): void'
>>> trans = kahlo.translators.MappingTranslator(kahlo.android.Signature, kahlo.jebandroid.JebFormatter.singleton, "/tmp/test_map.json")
>>> scm = kahlo.jebandroid.JebAndroidScheme(trans)
>>> scm.from_disp("LSomeClass;").to_runtime().to_frida()
'advg'
```

## Dependencies

If you want to use the signature parsers for Android and JEB, you need `pyparsing`.

## TODO

* Function hooking framework
* Better documentation, especially of the API
* More signature schemes

## License

GNU General Public License v3.0

See [LICENSE](/LICENSE) for full text.
