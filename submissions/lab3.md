# Lab 3 Submission — Secure Git

## Task 1

### SSH signing configuration

I created a new dedicated SSH key `~/.ssh/github_shnupel_signing.pub` for Git commit signing. The key is intended for the GitHub account `shnupel` and uses the email `ufamail.com2@gmail.com`.

Public key fingerprint:

```text
SHA256:8Cc9K1L4nIGVHaGxeJjALHhFS3dpHwc81SoOPtMICZY
```

```text
$ git config --global --get gpg.format
ssh

$ git config --global --get user.signingkey
/Users/pavel/.ssh/github_shnupel_signing.pub

$ git config --global --get commit.gpgsign
true

$ git config --global --get tag.gpgsign
true
```

I also configured `gpg.ssh.allowedSignersFile` as `~/.config/git/allowed_signers`. This file contains my email, the `git` namespace, and the complete SSH public key. It allows Git to verify the signature locally without a network connection.

The signed commit used for this submission is:

```text
The final signed commit output will be added after the rewritten history is pushed.
```

A signed commit makes the author claim stronger. Without signing, somebody can set my name and email in the Git configuration and create a commit that looks like it came from me. With SSH signing, GitHub can check that the commit was signed by the registered key and show the **Verified** badge. The badge does not prove that the code is safe, but it gives evidence about which key created the commit and helps with repudiation investigations.

GitHub commit link: to be added after the rewritten branch is pushed.

PR creation link: https://github.com/Shnupel/DevSecOps-Intro/pull/new/feature/lab3

## Task 2

### Pre-commit configuration

I created `.pre-commit-config.yaml` in the repository root:

```yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.30.1
    hooks:
      - id: gitleaks

  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v5.0.0
    hooks:
      - id: detect-private-key
        exclude: ^labs/lab6/vulnerable-iac/ansible/configure\.yml$
      - id: check-added-large-files
```

`v8.30.1` is a real gitleaks 8.x release. The other repository provides checks for private keys and unexpectedly large files. The private-key check has one narrow exclusion because the Lab 6 file is an intentional vulnerable training fixture. It contains a fake private-key block for demonstrating an infrastructure security issue. The exclusion is only for this exact path; it does not disable the check for normal files.

Installed tool versions were:

```text
pre-commit 4.6.2
gitleaks 8.30.1
git-filter-repo a40bce548d2c
```

The complete scan passed after adding the narrow fixture exclusion:

```text
Detect hardcoded secrets.................................................Passed
detect private key.......................................................Passed
check for added large files..............................................Passed
```

### Blocked fake secret commit

I created the fake token from the task in `submissions/leak-attempt.txt` and tried to commit it. The commit was rejected with exit status `1`:

```text
Detect hardcoded secrets.................................................Failed
- hook id: gitleaks
- exit code: 1

Finding:     GH_PAT=REDACTED
Secret:      REDACTED
RuleID:      github-pat
Entropy:     4.143943
File:        submissions/leak-attempt.txt
Line:        1
Fingerprint: submissions/leak-attempt.txt:github-pat:1

2:09PM INF 0 commits scanned.
2:09PM INF scanned ~48 bytes (48 bytes) in 20.4ms
2:09PM WRN leaks found: 1

detect private key.......................................................Passed
check for added large files..............................................Passed

--- commit exit status ---
1
--- last commit ---
f667747 Merge pull request #2 from Shnupel/lab2
```

The last commit stayed the same, so the secret commit was not created. I then removed the staged test file and the working-tree file.

### Tuning options

An `[allowlist]` entry in `.gitleaks.toml` is a rule exception for selected values, files, paths, or regular expressions. It can be useful for a safe example token that is confirmed to be fake, but it becomes unsafe if the value is copied into a real environment or if the rule is too broad and hides real credentials.

A path exclusion for `docs/` tells gitleaks not to scan every file in that directory. It can reduce false positives in documentation, but it becomes unsafe when documentation can contain copied configuration or real credentials, because a real secret in `docs/` will not be detected. A narrow allowlist is usually safer than excluding a whole directory.

## Bonus

### Sandbox before rewriting

I created a separate throwaway repository in `/tmp/lab3-bonus` and planted the same fake GitHub token in `config.txt` and `README.md`.

The history before rewriting was:

```text
e67e2d3 docs: usage notes
3e5b01d feat: empty log
4759713 feat: add config
10f7b7e init
```

The token count in the patch history was:

```text
$ git log -p | grep -c 'ghp_AAAA'
2
```

### filter-repo refusal and rewrite

I created the replacement file:

```text
<the planted fake ghp token from the task>==>[REDACTED]
```

The first command was:

```text
$ git filter-repo --replace-text /tmp/replace.txt
Aborting: Refusing to destructively overwrite repo history since
this does not look like a fresh clone.
  (expected at most one entry in the reflog for HEAD)
Please operate on a fresh clone instead.  If you want to proceed
anyway, use --force.
```

The sandbox was newly initialized, but it already had several local commits and reflog entries. I followed the message because this was a throwaway repository and ran:

```text
git filter-repo --force --replace-text /tmp/replace.txt
```

The output said:

```text
Parsed 4 commits
HEAD is now at 85ab8d0 docs: usage notes

New history written in 0.03 seconds; now repacking/cleaning...
Repacking your repo and cleaning out old unneeded objects
Completely finished after 0.12 seconds.
```

The rewritten history was:

```text
85ab8d0 docs: usage notes
5170acb feat: empty log
b830031 feat: add config
7a9ef59 init
```

The final checks were:

```text
$ git log -p | grep -c 'ghp_AAAA'
0

$ git log -p | grep -c 'REDACTED'
2
```

The commit hashes changed because the commit contents were changed. Rewriting history is only the cleanup step. The incident ends by **rotating or revoking the leaked credential** and then creating a new credential. The old token may already be copied by another person or stored in a remote, cache, fork, or backup, so deleting it from the visible Git history is not enough.

Two things surprised me:

1. `git filter-repo` refused the first run even though I had just created the sandbox. It checks the reflog and requires a fresh-clone-like repository unless `--force` is used.
2. gitleaks replaced the detected token with `REDACTED` in its output. This is useful because the scanner reports the rule and file without printing the complete secret.
