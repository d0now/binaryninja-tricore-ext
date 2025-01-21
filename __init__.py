from binaryninja.architecture import Architecture
from binaryninja.plugin import PluginCommand

from .tcext.absolute_addressing import AbsoluteAddressingHook

# workaround for TriCore architecture not being recognized by Binary Ninja at initial time (maybe not a core architecture?)
PluginCommand.register(
    "TriCore Extension Architecture Hook",
    "",
    lambda _: AbsoluteAddressingHook(Architecture['tricore']).register()
)