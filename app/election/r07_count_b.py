"""R7 - counting program B: piles and pointers.

Written to give the same answer as program A (same rules, see r07_count_a.py) but by a different method:
ballots sit in one pile per candidate. When a candidate is eliminated, their pile is handed on, one ballot
at a time, to the next remaining preference using a pointer on each ballot.
"""


def count(ballots, candidates, excluded=()):
    banned = set(excluded)
    standing = sorted(c for c in candidates if c not in banned)
    prefs = [[c for c in b if c not in banned] for b in ballots]      # skip excluded numbers up front
    piles = {c: [] for c in standing}
    pointer = [0] * len(prefs)
    exhausted = 0
    for i, p in enumerate(prefs):
        if p and p[0] in piles:
            piles[p[0]].append(i)
        else:
            exhausted += 1
    first_counts = {c: len(piles[c]) for c in standing}
    rounds = []
    still_in = list(standing)
    while still_in:
        tallies = {c: len(piles[c]) for c in still_in}
        continuing = sum(tallies.values())
        rounds.append({"tallies": dict(sorted(tallies.items())), "exhausted": exhausted, "eliminated": None})
        if continuing == 0:
            return {"winner": None, "rounds": rounds}
        majority = [c for c in still_in if tallies[c] * 2 > continuing]
        if majority:
            return {"winner": majority[0], "rounds": rounds}
        loser = sorted(still_in, key=lambda c: (tallies[c], first_counts[c], c))[0]
        rounds[-1]["eliminated"] = loser
        still_in.remove(loser)
        for i in piles.pop(loser):                    # hand the pile on
            p = prefs[i]
            pointer[i] += 1
            while pointer[i] < len(p) and p[pointer[i]] not in piles:
                pointer[i] += 1
            if pointer[i] < len(p):
                piles[p[pointer[i]]].append(i)
            else:
                exhausted += 1
    return {"winner": None, "rounds": rounds}
