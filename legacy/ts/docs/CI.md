# Where the gate runs

Three places check this code, and they check the same things on purpose. If one
of them ever passes something the others reject, that difference is a bug in the
gate, not a quirk to live with.

| | What runs it | Covers |
|---|---|---|
| **Before a push** | `.githooks/pre-push` → `npm run verify` | everything except the Docker images |
| **On a pull request** | [`.github/workflows/ci-self-hosted.yml`](../.github/workflows/ci-self-hosted.yml) | the same, on a clean checkout |
| **Before a deploy** | `npm run verify:docker`, by hand | the two Docker images |

`npm run verify` is the whole chain in one command: shared-rules sync, the
string catalogue, design tokens, a secret scan of the history, dependency
advisories at two thresholds, then both workspaces (type-check, lint, format,
tests with coverage, production build) and the end-to-end suite.

---

## Why the pull-request gate runs on this machine

This repository is private, so its GitHub Actions minutes are metered, and the
account's billing is blocked — every job in the hosted workflow died in under
thirteen seconds without executing a step. Self-hosted runners are not metered,
so the gate keeps working at no cost.

The two public repositories are unaffected. Public repositories get
GitHub-hosted minutes for free, and `lumeincc/lume` and `lumeincc/lume-mobile`
both build normally.

**This arrangement is safe here because the repository is private:** only
someone with write access can cause a workflow to run, so only trusted code
executes on the machine. The same setup on a public repository would let any
fork's pull request run arbitrary code locally, and must never be done for
`lumeincc/lume`.

[`ci.yml`](../.github/workflows/ci.yml) is kept, not deleted. It is the version
that runs on clean Linux VMs and covers the Docker builds, and its triggers are
removed rather than the file — a workflow that reds every pull request for a
billing reason teaches you to ignore red. To bring it back, restore the two
triggers at the top and retire the self-hosted one.

## The runner

Registered as `lume-local` on `lumeincc/lume-dev-version`, installed at
`C:\actions-runner`.

```powershell
.\scripts\runner.ps1 status     # is it up, and does it start at logon?
.\scripts\runner.ps1 start      # start it now
.\scripts\runner.ps1 stop       # stop it when you are not working
.\scripts\runner.ps1 install    # start it automatically at every logon
.\scripts\runner.ps1 uninstall  # stop starting it automatically
```

`install` registers a Scheduled Task rather than a Windows service, deliberately:
a service needs an elevated prompt, and it would run as SYSTEM — a different
Node, a different npm cache, no Playwright browsers. A build that fails only in
CI is the thing this is meant to avoid, not cause.

The runner went offline three times in one day before this existed, and each
time the symptom was a pull request whose checks sat in "queued" while nothing
looked wrong.

If the runner is offline when a pull request opens, the job does not fail — it
queues, and starts as soon as the runner comes back. A check that sits in
"waiting" is telling you the runner is down, not that the code is bad.

**Ports 3000 and 3001 must be free** while the job runs. The end-to-end suite
starts its own servers there, and the job's first step refuses to continue if
something is already listening. That check exists because Playwright's
`reuseExistingServer` would otherwise hand the tests a running dev server —
a different working tree from the commit being verified, producing a confident
result about the wrong code. Locally the same reuse is useful and stays on;
it is disabled only when `CI` is set.

## What the pull-request gate does not cover

The two Docker image builds. They need a running Docker daemon, and a step that
quietly skips itself when the daemon is down reports green for something it did
not check.

Run them before a deploy:

```bash
npm run verify:docker
```

The server image is the one that can break a release: `render.yaml` sets
`runtime: docker` and builds from `server/Dockerfile`, so a broken Dockerfile is
a failed deploy. The client image is for self-hosting — the hosted client goes
to Vercel, which does not use it.

## Secret scanning

`npm run check:secrets` scans the full history, not the working tree: a secret
that was committed and later removed is still in the objects being pushed.

It needs `gitleaks`. If it is missing the script says so and exits 0 rather than
passing silently — "not checked" is its own outcome and has to look like one.
The pull-request job does not rely on the machine having it: it downloads a
pinned version and verifies the published checksum before running it, because a
scanner fetched over the network is itself supply chain.

```bash
winget install gitleaks   # or brew install gitleaks
```

Known false positives live in `.gitleaksignore` with a reason each. Add
fingerprints there; never disable a rule.
