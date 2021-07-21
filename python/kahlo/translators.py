#
# translators : Generic utility translators
#

import json

from . import signature

class Exn(Exception): pass


class MappingExn(Exn): pass
class MappingTranslator(signature.Translator):
    '''Translator backed by a file containing a JSON object.

    The file should contain a JSON string representing an object. The
    key-value pairs of the object should correspond to the logical signature
    and the runtime signature of each entity. The format of the signatures
    should match that of the :formatter: argument.
    '''
    
    def __init__(self, sigcls, formatter, mapfile, ignore_misses=True):
        super().__init__(sigcls)
        self.formatter = formatter
        self.mapfile = mapfile
        self.ignore_misses = ignore_misses
        self.load_map()
    #enddef

    def load_map(self):
        with open(self.mapfile) as f:
            self.ltr_map = json.loads(f.read())
        #endwith
        self.rtl_map = dict(((v, k) for (k, v) in self.ltr_map.items()))
    #enddef

    def _lookup(self, themap, sig_from):
        disp_from = self.formatter.to_disp(sig_from)
        if disp_from in themap:
            disp_to = themap[disp_from]
            return self.formatter.from_disp(disp_to)
        elif self.ignore_misses:
            return sig_from
        else:
            raise MappingExn("Could not find signature {} in map.".format(disp_from))
        #endif
    #enddef

    def to_runtime(self, sig): return self._lookup(self.ltr_map, sig)
    def to_logical(self, sig): return self._lookup(self.rtl_map, sig)
    
#endclass
