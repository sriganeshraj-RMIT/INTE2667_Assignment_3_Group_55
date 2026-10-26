"""R7 - counting program A: round by round.

Rules (program B follows the very same rules, written a different way):
  1. Excluded candidates are treated as if they never stood: their numbers are skipped.
  2. Each ballot counts for its highest remaining preference.
  3. A candidate with MORE than half of the continuing votes wins.
  4. Otherwise the candidate with the fewest votes is eliminated.
     A tie is broken by the fewest FIRST-preference votes, then by the lowest candidate ID.

A ballot is a list of candidate IDs, first choice first.
"""
from collections import Counter


def count(ballots, candidates, excluded=()):
    alive = {c for c in candidates if c not in set(excluded)}

    def top(ballot):                              # the highest preference still in the race
        for c in ballot:
            if c in alive:
                return c
        return None

    first = Counter(top(b) for b in ballots)
    first_counts = {c: first.get(c, 0) for c in alive}
    rounds = []
    while alive:
        tallies = {c: 0 for c in alive}
        exhausted = 0
        for b in ballots:
            t = top(b)
            if t is None:
                exhausted += 1
            else:
                tallies[t] += 1
        continuing = sum(tallies.values())
        rounds.append({"tallies": dict(sorted(tallies.items())), "exhausted": exhausted, "eliminated": None})
        if continuing == 0:
            return {"winner": None, "rounds": rounds}
        for c, t in tallies.items():
            if t * 2 > continuing:
                return {"winner": c, "rounds": rounds}
        loser = min(alive, key=lambda c: (tallies[c], first_counts[c], c))
        rounds[-1]["eliminated"] = loser
        alive.discard(loser)
    return {"winner": None, "rounds": rounds}
