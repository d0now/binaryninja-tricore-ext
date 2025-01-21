from binaryninja.architecture import Architecture
from binaryninja.plugin import PluginCommand

from .tcext.absolute_addressing import AbsoluteAddressingHook
from .tcext.absolute_call import AbsoluteCallHook

def enable():
    AbsoluteAddressingHook(Architecture['tricore']).register()
    AbsoluteCallHook(Architecture['tricore']).register()

# workaround for TriCore architecture not being recognized by Binary Ninja at plugin loading time
# (maybe not a core architecture?)
PluginCommand.register(
    "TriCore Extension Architecture Hook",
    "",
    lambda _: enable()
)
