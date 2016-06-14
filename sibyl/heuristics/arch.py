"Module for architecture guessing"

from miasm2.analysis.binary import Container, ContainerUnknown


def container_guess(archinfo):
    """Use the architecture provided by the container, if any
    @archinfo: ArchHeuristic instance
    """

    cont = Container.from_stream(archinfo.stream)

    if isinstance(cont, ContainerUnknown) or not cont.arch:
        return {}

    return {cont.arch: 1}


class ArchHeuristic(object):
    """Provide heuristics to detect the architecture of a stream"""

    # Enabled passes
    # passes are functions taking 'self' and returning a dict: candidates -> estimated probability
    heuristics = [
        container_guess,
    ]

    def __init__(self, stream):
        self.stream = stream
        self._votes = None

    def do_votes(self):
        """Call heuristics and get back votes
        Use a cumulative linear strategy for comparison
        """
        votes = {}
        for heuristic in self.heuristics:
            for name, vote in heuristic(self).iteritems():
                votes[name] = votes.get(name, 0) + vote
        self._votes = votes

    @property
    def votes(self):
        """Cumulative votes for each candidates"""
        if not self._votes:
            self.do_votes()
        return self._votes

    def guess(self):
        """Return the best candidate"""
        sorted_votes = sorted(self.votes.iteritems(), key=lambda x:x[1])
        if not sorted_votes:
            # No solution
            return False
        best, _ = sorted_votes[-1]
        return best
