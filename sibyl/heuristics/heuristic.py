"Main class for heuristics"


class Heuristic(object):
    """Main class for heuristics, handle common methods related to them"""

    # Enabled passes
    # passes are functions taking 'self' and returning a dict:
    #    candidates -> estimated probability
    heuristics = []

    def __init__(self):
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
