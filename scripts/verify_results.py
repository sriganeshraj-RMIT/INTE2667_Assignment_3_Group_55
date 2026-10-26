"""R13 - check a published result from outside the system.

    python scripts/verify_results.py http://localhost:5001 <election_id>

It downloads the published result and checks the signature with verify() from app/common/crypto.py.
(The signing key must be configured the way Jaswanth's R10 code expects, for example in the environment.)
"""
import json
import os
import sys
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))   # lets this file import "app"

from app.common.crypto import verify           # noqa: E402  (must come after the line above)
from app.election.r07_count import canonical   # noqa: E402


def main(base_url, election_id):
    url = f"{base_url.rstrip('/')}/election/{election_id}/results"
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            published = json.load(resp)
    except urllib.error.HTTPError as e:
        print(f"The server answered {e.code}: no published result for this election.")
        return 2
    except urllib.error.URLError:
        print("Could not reach the server. Is it running?")
        return 2
    ok = bool(verify(canonical(published["result"]), published["signature"]))
    print("Signature is VALID: this is exactly what was signed." if ok
          else "Signature is NOT valid: do not trust this result.")
    return 0 if ok else 1


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    sys.exit(main(sys.argv[1], sys.argv[2]))
