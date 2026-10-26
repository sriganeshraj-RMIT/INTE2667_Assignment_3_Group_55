"""Helpers for tests that need a REAL ballot box (R4's batches and R20's chain) without a Redis server.

`use_fake_redis` swaps the Redis that R4 talks to for a tiny in-memory copy; everything else (the shuffled batch
write, the chain, the signed head) is the real code.
"""
from app.ballot import r04_ballot_box as box


class FakeRedis:
    """Just enough of Redis for R4's waiting list: rpush, lrange, delete and a pipeline."""

    def __init__(self):
        self.lists = {}

    def rpush(self, key, *values):
        self.lists.setdefault(key, []).extend(v.encode() if isinstance(v, str) else v for v in values)
        return len(self.lists[key])

    def lrange(self, key, start, end):
        return list(self.lists.get(key, []))                 # R4 only ever asks for the whole list

    def delete(self, key):
        return 1 if self.lists.pop(key, None) is not None else 0

    def pipeline(self, transaction=True):
        return _FakePipeline(self)


class _FakePipeline:
    def __init__(self, redis):
        self.redis, self.calls = redis, []

    def lrange(self, *args):
        self.calls.append(("lrange", args))

    def delete(self, *args):
        self.calls.append(("delete", args))

    def execute(self):
        return [getattr(self.redis, name)(*args) for name, args in self.calls]


def use_fake_redis(monkeypatch):
    """From now on R4 uses an in-memory Redis. Returns it, so a test can look inside."""
    fake = FakeRedis()
    monkeypatch.setattr("app.ballot.r04_ballot_box.get_redis", lambda: fake)
    return fake


def wait_in_box(fake, election_id, sealed_ballots):
    """Ballots that have arrived but are still WAITING in the list (the last, part-full batch)."""
    for sealed in sealed_ballots:
        fake.rpush(box._pending_key(election_id), sealed)


def store_in_box(fake, election_id, sealed_ballots):
    """Ballots written through the real R4 + R20 path: shuffled batch, chain links, signed head."""
    wait_in_box(fake, election_id, sealed_ballots)
    return box.flush_pending(election_id)
