# Watchword — Repository hardening runbook

The controls `07-supply-chain.md` §4 lists as `[planned]` need repository-admin access rather than
code. This is the procedure, as `gh` commands, in an order that does not lock you out.

Context these commands assume, verified 2026-10-13: `ericsuh/watchword` is **public** and
**user-owned**, default branch `main`. Public repos get branch protection, rulesets, and secret
scanning on every plan, so none of this needs a paid plan. A user-owned repo has no teams, which
changes the review settings in step 4.

> These are composed from the GitHub REST API contracts, not executed here — `gh` is not
> authenticated in the environment the rest of this work was validated in. Run them yourself and
> check step 9's verification output.

## Read this first: two ways to lock yourself out

**1. Required signatures with no signing set up.** As of this writing `git log --format='%G?'`
reports `N` (unsigned) for every commit on this branch, and `commit.gpgsign` is unset. Turning on
required signatures before step 2 means your next push is rejected.

**2. Required signatures while PR #1 is open.** Protection requiring signatures rejects a merge
whose commits are unsigned. PR #1's commits are unsigned. So either merge PR #1 first and enable
signatures after (simplest), or re-sign its commits:

```sh
# Only on a branch nobody else has checked out.
git rebase --exec 'git commit --amend --no-edit -S' main
git push --force-with-lease
```

Steps 1–7 are safe to run with PR #1 open. Step 8 (signatures) is the one to defer.

## 1. Make the default token read-only and allow only GitHub-owned actions

The highest-value pair, and it pairs directly with the SHA pinning in `07-supply-chain.md` §3.1.
With `setup-xcode` removed, the actions in use are `actions/checkout` and `actions/upload-artifact`,
both GitHub-owned, plus one exception: `anthropics/claude-code-action` in `claude-pr.yml`
(`07-supply-chain.md` §3.2), a composite action that itself runs `oven-sh/setup-bun`. Both are
allowed by name at the SHAs the workflow and the action pin; nothing else third-party may run, and a
workflow naming anything else fails to start.

```sh
# Default GITHUB_TOKEN is read-only; workflows cannot approve PRs.
gh api -X PUT repos/ericsuh/watchword/actions/permissions/workflow \
  -f default_workflow_permissions=read \
  -F can_approve_pull_request_reviews=false

# Actions are enabled, but only a selected set may run.
gh api -X PUT repos/ericsuh/watchword/actions/permissions \
  -F enabled=true -f allowed_actions=selected

# That selected set is: GitHub-owned, plus claude-code-action and the setup-bun it pins, each at one SHA.
# No other third-party action, not even "verified creator".
gh api -X PUT repos/ericsuh/watchword/actions/permissions/selected-actions \
  --input - <<'JSON'
{
  "github_owned_allowed": true,
  "verified_allowed": false,
  "patterns_allowed": [
    "anthropics/claude-code-action@8041f1d17e0e7d2f2cfe35002962e9f26237c0bb",
    "oven-sh/setup-bun@0c5077e51419868618aeaa5fe8019c62421857d6"
  ]
}
JSON
```

If another third-party action is ever genuinely needed, add it to `patterns_allowed` **pinned to a
SHA** (`owner/repo@<40-hex>`), which `mise run audit:actions` also requires, on every pull request. Bumping
`claude-code-action` means updating both entries: its own SHA, and the `setup-bun` SHA in that
release's `action.yml`.

### 1.1 The `screenshots` label

`screenshots.yml` (`07-supply-chain.md` §3.2) captures a pull request's screens when the pull request carries the
`screenshots` label. It uses GitHub-owned actions only, so the allowed-actions list above needs no entry for it, and
the read-only default token is right for it: its one comment job asks for `pull-requests: write` in the file.
The label exists: it was created, plain grey and without a description, the first time it was applied through the
API. Give it a description, or recreate it in a repository that lacks it, with:

```sh
gh label create screenshots --repo ericsuh/watchword --color 5319E7 --force \
  --description "Capture the app's screens for this pull request and attach them (screenshots.yml)"
```

Applying a label needs triage access, which is who may start a capture this way. (The other way, a line that is
exactly `[screenshots]` in a head commit's message, works only on a branch of this repository, where pushing needs
write access.) GitHub treats label names that differ only in case as one label, and so does the workflow, so a
label created as `Screenshots` works too. The comment job asks for `actions: read` beside `pull-requests: write`, to
list the run's own artifacts; neither needs a repository setting changed. Do not add any `Screenshots` job
to the required checks in step 5: the workflow skips most pull requests, and a required check that is skipped counts
as passing while one that never reports blocks the merge.

### 1.2 The `staging` environment

`claude-pr.yml` holds the repository's one secret (`07-supply-chain.md` §3.2), and its `authorize` job cannot be what
protects it: on three of its four triggers GitHub runs the pull request's own copy of the workflow, and any workflow on
a branch of this repository may name `environment: staging`. What decides who reads the secret is the environment.
Nothing in the tree creates it or shows how it is set, so it is created here and printed in step 9.

```sh
# The secret lives in the environment and nowhere else. A repository secret of either name would be readable by
# every workflow, whatever the environment's rules; this should print nothing.
gh secret list --repo ericsuh/watchword

# One required reviewer (the owner), and only selected refs may deploy. `prevent_self_review` stays false: on a
# single-owner repository the person who asks for a review is the only one who can approve it.
owner_id=$(gh api users/ericsuh --jq .id)
gh api -X PUT repos/ericsuh/watchword/environments/staging --input - <<JSON
{
  "wait_timer": 0,
  "prevent_self_review": false,
  "reviewers": [{ "type": "User", "id": $owner_id }],
  "deployment_branch_policy": { "protected_branches": false, "custom_branch_policies": true }
}
JSON

# The refs the workflow runs from: the default branch (`issue_comment`) and pull-request merge refs (the other
# three triggers). Nothing else.
gh api -X POST repos/ericsuh/watchword/environments/staging/deployment-branch-policies \
  -f name=main -f type=branch
gh api -X POST repos/ericsuh/watchword/environments/staging/deployment-branch-policies \
  -f name='refs/pull/*/merge' -f type=branch

# One of the two, as an environment secret (the command prompts for the value; it is never on a command line).
gh secret set CLAUDE_CODE_OAUTH_TOKEN --repo ericsuh/watchword --env staging
```

Whether GitHub matches `refs/pull/*/merge` as written is not something these commands can show: after running them,
open a pull request and confirm that a `Review` run reaches the approval prompt rather than being refused for its
ref, and adjust the pattern if it is refused.

With the reviewer set, every Claude run waits for an approval, the owner's own included. That approval is the
control, so it is worth ten seconds each time:

- **Which workflow is asking.** The pending deployment names its workflow and job. It should be `Claude PR`, job
  `Review` or `Respond`. A deployment to `staging` from any other workflow is a workflow someone added to reach the
  secret: reject it.
- **Whether the pull request touches `.github/`.** On `pull_request`, `pull_request_review` and
  `pull_request_review_comment`, what runs with the secret is the pull request's copy of the workflow files. If the
  pull request changes anything under `.github/`, read that change before approving, or reject and ask for the
  review with an `@claude` comment instead: `issue_comment` runs the default branch's copy.
- **Whose pull request it is.** An approval on a stranger's pull request is the case `07-supply-chain.md` §3.2
  records as open: the review reads text its author wrote, with the secret in reach.

If the pull-request triggers are ever dropped from `claude-pr.yml`, remove the `refs/pull/*/merge` policy in the same
change: the environment can then admit the default branch alone, and a pushed branch can no longer ask at all.

## 2. Set up commit signing locally (prerequisite for step 8)

SSH signing is the least friction on macOS if you already have an SSH key.

```sh
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519.pub
git config --global commit.gpgsign true
git config --global tag.gpgsign true

# Register the SAME key again, as a signing key. An authentication key does not
# make commits show as Verified; this is a separate key type on GitHub.
gh ssh-key add ~/.ssh/id_ed25519.pub --type signing --title "watchword commit signing"

# Confirm: the new commit should report "G".
git commit --allow-empty -m "signing check" && git log --format='%h %G?' -1
git reset --hard HEAD~1
```

## 3. Enable secret scanning and push protection

Free on public repos. Push protection is the one that matters — it blocks a credential at
`git push` instead of telling you about it afterwards.

```sh
gh api -X PATCH repos/ericsuh/watchword --input - <<'JSON'
{
  "security_and_analysis": {
    "secret_scanning": { "status": "enabled" },
    "secret_scanning_push_protection": { "status": "enabled" },
    "secret_scanning_validity_checks": { "status": "enabled" }
  }
}
JSON

gh api -X PUT repos/ericsuh/watchword/vulnerability-alerts
```

`automated-security-fixes` is deliberately **not** enabled: it opens auto-merging dependency PRs,
and `07-supply-chain.md` requires a human to read the diff between two pins.

### 3.1 Code scanning (CodeQL default setup)

Already enabled, and the only CI that runs without a workflow file in the tree. It surfaces on
pull requests as the `Analyze (swift)` check. Confirm the configuration rather than assuming it:

```sh
gh api repos/ericsuh/watchword/code-scanning/default-setup
# Expect: state "configured", languages ["swift"], query_suite "default",
#         threat_model "remote", schedule "weekly".
```

To change the query suite — `security-extended` trades more findings for more false positives,
which is usually the right trade on a password manager:

```sh
gh api -X PATCH repos/ericsuh/watchword/code-scanning/default-setup --input - <<'JSON'
{ "state": "configured", "query_suite": "extended" }
JSON
```

Read findings from the CLI so a review does not depend on the web UI:

```sh
gh api repos/ericsuh/watchword/code-scanning/alerts \
  --jq '.[] | {rule: .rule.id, severity: .rule.security_severity_level, state,
               path: .most_recent_instance.location.path}'
```

**`Analyze (swift)` is not in the step 5 required-check list, and that is a live choice rather than
a settled one.** Arguments both ways, since this is exactly the sort of thing that gets decided by
accident:

- *For requiring it:* it does real work, not a check that passes by doing nothing. A memory-safety or injection finding landing on `main` is the kind of
  regression this project cares about most.
- *Against:* the queries are versioned by GitHub, so a query-pack update can turn a green `main`
  red without any change here — a different failure mode from the rest of the list, where a red
  check always means a commit broke something. It also blocks merges on an analysis that has no
  pinned version (`07-supply-chain.md` §3.4).

Recommendation: leave it advisory until the first month of alerts shows the false-positive rate,
then require it. It cannot join `Required checks` (that job only sees `ci.yml`'s own jobs), so if you
do require it, add `"Analyze (swift)"` to `contexts` in step 5 **and** to the expected-count sentence
in step 9 — and re-check both after ever enabling a second language,
because the context name is derived from the language set.

## 4. Merge hygiene

```sh
gh api -X PATCH repos/ericsuh/watchword --input - <<'JSON'
{
  "allow_squash_merge": true,
  "allow_rebase_merge": true,
  "allow_merge_commit": false,
  "delete_branch_on_merge": true,
  "allow_auto_merge": false,
  "web_commit_signoff_required": true
}
JSON
```

`allow_auto_merge: false` is deliberate: auto-merge lands a PR the moment checks go green, which
removes the human read of the diff that is the actual control.

## 5. Branch protection on `main`

Require one check, `Required checks`: the last job in `ci.yml`, which needs every other job there
and fails unless each succeeded — both package-test legs, the adversarial suite, strict memory
safety, lint (with the script tests and the action-pinning and mise-pin audits), the macOS and
iOS-simulator app tests and the two Release builds on the `xcode-27` (macOS 27) runner. The
individual jobs still show as their own checks on a pull request; they are not listed here because
their names carry the runner and Xcode (`Package tests (Xcode 27 / macOS 27)`), and a required
check that no longer reports blocks every merge until someone edits this setting. That is what
moving from macOS 26 to macOS 27 would otherwise have done.

If `main` already requires the old per-job list (`Package tests (Xcode 26 / macOS 26)` and the
rest), apply this before merging the change that renamed them, or that pull request cannot merge.

```sh
gh api -X PUT repos/ericsuh/watchword/branches/main/protection --input - <<'JSON'
{
  "required_status_checks": {
    "strict": true,
    "contexts": [
      "Required checks"
    ]
  },
  "enforce_admins": true,
  "required_pull_request_reviews": {
    "required_approving_review_count": 0,
    "dismiss_stale_reviews": true,
    "require_code_owner_reviews": false,
    "require_last_push_approval": false
  },
  "restrictions": null,
  "required_linear_history": false,
  "allow_force_pushes": false,
  "allow_deletions": false,
  "block_creations": false,
  "required_conversation_resolution": true,
  "lock_branch": false,
  "allow_fork_syncing": true
}
JSON
```

Three choices worth understanding rather than copying:

- **`required_approving_review_count: 0`.** GitHub does not let you approve your own pull request.
  On a solo repo any value ≥ 1 means you can never merge your own work without a second account.
  Zero still forces every change through a PR with passing checks; it only drops the approval
  click. Raise it to 1 and set `require_code_owner_reviews: true` the day a second person joins —
  that is also when `.github/CODEOWNERS` (step 6) gains teeth.
- **`enforce_admins: true`.** The rules apply to you too, which is the point, but it means an
  emergency fix needs protection temporarily lifted:
  `gh api -X DELETE repos/ericsuh/watchword/branches/main/protection/enforce_admins`, then
  `-X POST` the same path to restore it. Prefer a PR.
- **`strict: true`** requires a branch to be up to date with `main` before merging. It is the
  setting that stops two independently-green PRs from combining into a red `main`.

`required_linear_history` is left `false` so that resolving a conflict by merging `main` into a
feature branch stays possible. Set it to `true` if you would rather always rebase.

## 6. CODEOWNERS

A workflow edit is code execution in CI, so `.github/` deserves a named owner. Commit this:

```sh
mkdir -p .github && cat > .github/CODEOWNERS <<'EOF'
# A change under .github/ is code execution in CI, and Package.swift can execute code at
# build time (Swift macros, plugins). Both get a named reviewer.
/.github/        @ericsuh
/Package.swift   @ericsuh
/docs/0*-*.md    @ericsuh
EOF
```

On a solo repo this is documentation and routing, not enforcement — see the note in step 5.

## 7. Protect release tags

The classic tag-protection endpoint (`/repos/{owner}/{repo}/tags/protection`) is deprecated;
rulesets replace it. This prevents a published release tag from being **moved or deleted** while
still letting you create new ones.

```sh
gh api -X POST repos/ericsuh/watchword/rulesets --input - <<'JSON'
{
  "name": "Protect release tags",
  "target": "tag",
  "enforcement": "active",
  "conditions": {
    "ref_name": { "include": ["refs/tags/v*"], "exclude": [] }
  },
  "rules": [
    { "type": "deletion" },
    { "type": "non_fast_forward" }
  ],
  "bypass_actors": []
}
JSON
```

A moved release tag is how a reviewed commit gets swapped for an unreviewed one after the fact,
which is exactly what the build-provenance attestation in `07-supply-chain.md` §4 is meant to
make detectable.

## 8. Require signed commits — last, and only after steps 2 and the PR #1 note

```sh
gh api -X POST repos/ericsuh/watchword/branches/main/protection/required_signatures
```

To undo if it bites: `gh api -X DELETE .../required_signatures`.

## 9. Verify

```sh
echo "— branch protection —"
gh api repos/ericsuh/watchword/branches/main/protection \
  --jq '{checks: .required_status_checks.contexts,
         strict: .required_status_checks.strict,
         admins: .enforce_admins.enabled,
         reviews: .required_pull_request_reviews.required_approving_review_count,
         force_push: .allow_force_pushes.enabled,
         deletions: .allow_deletions.enabled,
         signatures: .required_signatures.enabled,
         conversations: .required_conversation_resolution.enabled}'

echo "— actions policy —"
gh api repos/ericsuh/watchword/actions/permissions --jq '{enabled, allowed_actions}'
gh api repos/ericsuh/watchword/actions/permissions/selected-actions
gh api repos/ericsuh/watchword/actions/permissions/workflow

echo "— staging environment (the one secret; step 1.2) —"
gh api repos/ericsuh/watchword/environments/staging \
  --jq '{reviewers: [.protection_rules[] | select(.type == "required_reviewers") | .reviewers[].reviewer.login],
         self_review_prevented: [.protection_rules[] | select(.type == "required_reviewers") | .prevent_self_review],
         branch_policy: .deployment_branch_policy}'
gh api repos/ericsuh/watchword/environments/staging/deployment-branch-policies \
  --jq '[.branch_policies[] | {name, type}]'
gh api repos/ericsuh/watchword/environments/staging/secrets --jq '[.secrets[].name]'
gh api repos/ericsuh/watchword/actions/secrets --jq '[.secrets[].name]'

echo "— security features —"
gh api repos/ericsuh/watchword --jq '.security_and_analysis'

echo "— code scanning (no workflow file; settings only) —"
gh api repos/ericsuh/watchword/code-scanning/default-setup \
  --jq '{state, languages, query_suite, schedule}'

echo "— rulesets —"
gh api repos/ericsuh/watchword/rulesets --jq '.[] | {name, target, enforcement}'
```

Expected: one context, `Required checks`, with `strict: true`, `admins: true`, no force-push, no deletions,
`allowed_actions: "selected"` with `github_owned_allowed: true` and `patterns_allowed` holding exactly the two
SHA-pinned entries above,
`default_workflow_permissions: "read"`, secret scanning and push protection `enabled`, code
scanning `configured` for `["swift"]`, and one active tag ruleset.

For `staging`: `reviewers: ["ericsuh"]` (an empty list means anyone who can push a branch can run a job that reads
the secret), `branch_policy` with `custom_branch_policies: true` and `protected_branches: false`, exactly the two
policies `main` and `refs/pull/*/merge`, one environment secret (`CLAUDE_CODE_OAUTH_TOKEN` or `ANTHROPIC_API_KEY`),
and an empty list of repository secrets. A 404 on the first command means the environment was never created with
rules: GitHub makes an unprotected one the first time a workflow names it.

One context is correct only while `Analyze (swift)` stays advisory (step 3.1). If that decision
is revisited, this sentence is the second place to update.

## Optional: Dependabot for action pins

Keeps the SHA pins from going stale. Opens PRs; **do not** pair it with auto-merge, because the
control is a human reading the diff between the old and new SHA.

```sh
mkdir -p .github && cat > .github/dependabot.yml <<'EOF'
version: 2
updates:
  - package-ecosystem: github-actions
    directory: "/"
    schedule:
      interval: monthly
    # Keep SHA pins: Dependabot rewrites the pin and updates the trailing version comment.
    open-pull-requests-limit: 3
EOF
```

There is deliberately no `swift` ecosystem entry: the package has no dependencies, and
`07-supply-chain.md` §2 enforces that in CI.
