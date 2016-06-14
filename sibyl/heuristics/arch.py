"Module for architecture guessing"

from miasm2.analysis.binary import Container, ContainerUnknown

from sibyl.heuristics.heuristic import Heuristic


def container_guess(archinfo):
    """Use the architecture provided by the container, if any
    @archinfo: ArchHeuristic instance
    """

    cont = Container.from_stream(archinfo.stream)

    if isinstance(cont, ContainerUnknown) or not cont.arch:
        return {}

    return {cont.arch: 1}


class ArchHeuristic(Heuristic):
    """Provide heuristics to detect the architecture of a stream"""

    # Enabled passes
    heuristics = [
        container_guess,
    ]

    def __init__(self, stream):
        super(ArchHeuristic, self).__init__()
        self.stream = stream
