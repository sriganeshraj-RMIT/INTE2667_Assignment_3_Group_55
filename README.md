# Electronic Voting Platform - Prototype (INTE2667 Assignment 3, Part Three)

A security-focused prototype of the AEC Electronic Voting Platform. It implements the 20 security requirements (R1 to R20) from Part One, using the solutions chosen in Part Two.

**Team:** Jaswanth Mahesh (s4184071), Akash Sunder (s4176087), Srikanth Tanikonda (s4188136), Sriganesh Raj (s4189210)

---

## 1. Tech stack

| Part | Tool | Why |
|---|---|---|
| Web app and REST API | Python 3.12, Flask (blueprints) | Used in the course labs |
| Pages | Jinja2 templates + Bootstrap 5 | Server-rendered, auto-escaped (XSS protection) |
| Database | MySQL 8 (`identity_db` and `ballot_db`) | Separate databases keep voter identity apart from ballots (R1) |
| Sessions and counters | Redis 7 | Rate limiting (R15), sessions |
| Email | MailHog | Fake mail server; stands in for the posted enrolment code (R2) |
| Containers | Docker Compose | Same setup on every machine |
| Tests | pytest | Unit tests for every requirement |

---

## 2. Prerequisites (install once)

1. **Docker Desktop**: https://www.docker.com/products/docker-desktop. Open it and wait until it says "running".
2. **Python 3.12 or newer**: check with `python3 --version`.
3. **Git**: check with `git --version`. Your git email must match your GitHub account, or your commits won't count towards you:
   ```bash
   git config --global user.name "Your Name"
   git config --global user.email "the-email-on-your-github-account"
   ```

---

## 3. Getting started (first time)

### Step 1 - Clone the repo
```bash
git clone <repo-url>
cd <repo-folder>
```

### Step 2 - Create your `.env` file
`.env` holds your local secrets. It is ignored by git and must **never** be committed.
```bash
cp .env.example .env
```
Open `.env` and replace each `change-me` with a value of your choice (anything works locally, for example `rootpass123`).
**Important:** the password in `DATABASE_URL` must be the same as `MYSQL_ROOT_PASSWORD`.

### Step 3 - Start everything with Docker
```bash
docker compose up --build
```
The first run takes a few minutes while images download. Leave this terminal open, because it shows the logs.

### Step 4 - Check that it works
| Open this | You should see |
|---|---|
| http://localhost:5001/health | `{"status": "ok"}` |
| http://localhost:8025 | The MailHog inbox (empty for now) |

The app runs on **port 5001**, not 5000, because macOS uses port 5000 for AirPlay.

### Step 4b - Use the GUI
1. Put `DEV_SEED_PASSWORD=` (12 or more characters) in your `.env`, then give every seed account that password:
   ```bash
   docker compose exec app flask auth seed-dev-passwords
   ```
2. Open **http://localhost:5001** and sign in as any seed account (`voter@evp.test`, `officer@evp.test`,
   `delegate@evp.test`, `delegate2@evp.test`, `custodian@evp.test`, `counter@evp.test`, `auditor@evp.test`,
   `admin@evp.test`) with that password.
3. Second step: staff scan the QR code with an authenticator app (or type the key); the voter can ask for an
   emailed code, which arrives in MailHog at http://localhost:8025.
4. Each role sees its own tools in the top bar. Election times are in **UTC**.
5. For a demo election that opens in a few minutes: `docker compose exec app flask ui demo-election`, then sign in as
   the delegate and lock it, and as the custodian and run the key ceremony, before it opens.

Pages: `/` home, `/elections` (signed ballots and results), `/receipt`, `/enrol`, `/vote` (voter),
`/staff/elections`, `/staff/access`, `/staff/exclusions`, `/staff/officer`, `/audit`.

### Step 5 - Stop it
Press `Ctrl+C` in the Docker terminal, then run:
```bash
docker compose down
```

---

## 4. Running tests (without Docker)

Tests use Flask's test client, so they don't need Docker or MySQL running.

```bash
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
pytest -v
```

**Always run `pytest` from the project root folder**, not from inside `app/`. Otherwise imports break and stray cache folders appear.

If you install a new package, add it to `requirements.txt`:
```bash
pip install <package>
pip freeze > requirements.txt
```
Then rebuild Docker with `docker compose up --build`.

---

## 5. Project structure

```
.
├── app/
│   ├── __init__.py          # create_app(): builds the Flask app and registers blueprints
│   ├── auth/                # sign-in, MFA, roles            (R8, R12, R14)
│   ├── enrolment/           # enrolment, address change      (R2, R9, R15)
│   ├── ballot/              # voting pass, casting, storage  (R1, R3, R4, R5, R6, R20)
│   ├── election/            # candidates, counting, results  (R7, R10, R13, R19)
│   ├── audit/               # activity log, monitoring       (R11, R17)
│   ├── common/              # SHARED helpers - everyone uses these
│   │   ├── auth.py          # login_required, role_required, mfa_required, current_user
│   │   ├── audit.py         # audit(event, actor_id, details)
│   │   ├── crypto.py        # sign, verify, keyed_hash, chain_hash
│   │   └── validate.py      # validate(schema, payload)
│   └── templates/
│       └── base.html        # shared page layout - every page extends this
├── db/init/                 # SQL run automatically when the MySQL container first starts
│   ├── 01_identity.sql      # identity_db: accounts + seed users
│   ├── 02_ballot.sql        # ballot_db: ballots, audit_log
│   └── 03_election.sql      # elections, candidates + seed election
├── tests/                   # pytest tests
├── Dockerfile               # how the Flask container is built
├── docker-compose.yml       # app + MySQL + Redis + MailHog
├── requirements.txt
├── .env.example             # template for .env (committed)
└── .env                     # your real secrets (NOT committed)
```

Each section folder (`auth`, `enrolment`, and so on) has two files:
- `__init__.py` creates the blueprint (`bp`). Don't change it.
- `routes.py` is where you write your endpoints.

---

## 6. How to add an endpoint

Write it in the `routes.py` of the right section. The first line of every `routes.py` must be `from . import bp`.

```python
# app/enrolment/routes.py
from flask import request, jsonify
from . import bp
from app.common.auth import login_required, role_required, mfa_required
from app.common.audit import audit
from app.common.validate import validate

ADDRESS_SCHEMA = {
    "street":   {"type": str, "max_length": 200, "required": True},
    "postcode": {"type": str, "max_length": 4,   "required": True},
}

@bp.post("/address")                 # final URL: /enrolment/address
@login_required
@mfa_required
def change_address():
    data = validate(ADDRESS_SCHEMA, request.get_json() or {})
    # ... your logic ...
    audit("ENROLMENT_ADDRESS_CHANGE_REQUESTED", actor_id="<user id>", details={"postcode": data["postcode"]})
    return jsonify({"status": "pending"}), 202
```

Then add a test in `tests/`, for example `tests/test_enrolment.py`.

---

## 7. Team conventions (please follow these)

### Imports
Always use absolute imports from `app.common`:
```python
from app.common.auth import login_required
```

### Roles (use these exact strings)
`voter`, `officer`, `delegate`, `counting_officer`, `auditor`, `custodian`, `admin`

### Error responses (all endpoints)
```json
{"error": "VALIDATION_FAILED", "message": "postcode is required"}
```
`error` is an upper-case code; `message` is human-readable. Never return stack traces or SQL errors to the user.

### Audit event names
`AREA_ACTION` in upper case, for example `AUTH_LOGIN_FAILED`, `BALLOT_CAST`, `ELECTION_DEFINITION_SIGNED`. Never put a voter's identity in a ballot-side event (R1).

### Security rules for every piece of code
- Validate every input with `validate()` (R18).
- Use the ORM or parameterised queries only. **Never** build SQL with f-strings or `+`.
- Protect every endpoint with `login_required` / `role_required`; deny by default (R8).
- Never commit secrets, keys or `.env`.
- Never log passwords, codes, tokens or ballot contents.

---

## 8. The shared `common/` helpers (stubs for now)

These have the right names and inputs, but some don't do the real work yet. **Call them anyway.** They are filled in under Set A, and your code will start working properly without any changes.

| Function | Status | Filled in by |
|---|---|---|
| `validate(schema, payload)` | Working (basic checks) | R18 |
| `login_required`, `role_required(*roles)`, `current_user()` | Stub (lets everything through) | R8 |
| `mfa_required` | Stub | R12 |
| `audit(event, actor_id, details)` | Stub (prints to console) | R17 |
| `sign`, `verify` | Stub | R10 / R13 |
| `keyed_hash` | Stub | R9 |
| `chain_hash(prev, data)` | Working | R17 / R20 |

Seed accounts in `01_identity.sql` (`voter@evp.test`, `officer@evp.test`, and so on, one per role) have placeholder passwords. Real login works once R8 is done.

---

## 9. Work split (5 issues each, in dependency order)

| Set | Owner | Issues (in order) |
|---|---|---|
| A - Foundation | Jaswanth | R18 → R12 → R8 → R17 → R10 |
| B - Enrolment and identity | Akash | R2 → R9 → R15 → R3 → R1 |
| C - Ballot protection | Srikanth | R5 → R4 → R20 → R6 → R11 |
| D - Staff controls and results | Sriganesh | R14 → R19 → R7 → R13 → R16 |

You don't need to wait for Set A. Use the stubs, and your code will pick up the real versions when they are merged.

---

## 10. Git workflow

### Golden rules
- **Never commit directly to `main`.** Always work on a branch.
- One branch per issue.
- Small, meaningful commits (aim for 10 to 15 each over the project). Marks depend on individual commit history.

### Step by step
```bash
# 1. Get the latest main
git checkout main
git pull

# 2. Create your branch (name it after the issue)
git checkout -b feature/R2-enrolment-verification

# 3. Work, then commit often
git add <files>
git commit -m "R2: add posted-code redemption endpoint (#2)"

# 4. Push your branch
git push -u origin feature/R2-enrolment-verification
```

5. On GitHub, open a **Pull Request** into `main` and write `Closes #<issue number>` in the description.
6. Ask one teammate to review it.
7. Merge with **"Create a merge commit"**, not "Squash", so everyone's individual commits stay in the history.

### Commit message format
```
R<number>: <what you did, in present tense> (#<issue number>)
```
Examples: `R3: add unique constraint on mark-off (#3)`, `R15: rate-limit status check with Redis (#15)`

### Keeping your branch up to date
```bash
git checkout main
git pull
git checkout <your-branch>
git merge main
```

---

## 11. Database

### Look inside MySQL
```bash
docker compose exec db mysql -uroot -p
```
Enter the `MYSQL_ROOT_PASSWORD` from your `.env`, then try:
```sql
SHOW DATABASES;
USE identity_db;
SELECT email, role, status FROM accounts;
```

### Changing tables
Edit the right file in `db/init/`. The scripts only run when the database is **first created**, so after editing them you must reset:
```bash
docker compose down -v      # -v deletes the database volume (all data)
docker compose up --build
```

---

## 12. Troubleshooting

| Problem | Fix |
|---|---|
| `port is already allocated` | Another program is using the port. Stop it, or change the left-hand number in `docker-compose.yml` (for example `"5002:5000"`). |
| `Access denied for user 'root'` | The password in `DATABASE_URL` doesn't match `MYSQL_ROOT_PASSWORD`, or the database was created with an old password. Fix `.env`, then `docker compose down -v`. |
| Table changes not showing | Run `docker compose down -v`, then `docker compose up --build`. |
| `ModuleNotFoundError: app` in pytest | Run `pytest` from the project root, with the venv activated. |
| `ImportError` on startup | A section is missing `routes.py`, or its `routes.py` doesn't start with `from . import bp`. |
| New package not found in Docker | Add it to `requirements.txt`, then `docker compose up --build`. |
| Docker command not found / can't connect | Open Docker Desktop and wait until it is running. |

---

## 13. Useful commands

| Command | What it does |
|---|---|
| `docker compose up --build` | Build and start everything |
| `docker compose up -d` | Start in the background |
| `docker compose logs -f app` | Follow the Flask logs |
| `docker compose down` | Stop everything (keeps data) |
| `docker compose down -v` | Stop and wipe the database |
| `docker compose exec app bash` | Open a shell inside the Flask container |
| `pytest -v` | Run all tests |
| `pytest tests/test_health.py -v` | Run one test file |
