""".github/scripts/cloud-setup.sh, run as it is against stand-ins for `curl`, `gpg`, `apt-get` and `mise`, with every path
it writes moved below a scratch directory (WATCHWORD_SETUP_TEST_ROOT).

The script runs as root on the VM that holds a cloud session's checkout, so which toolchain it will install is a
security decision. It verified the release tarball against a pinned key, and then answered a failed verification by
running a second installer, swiftly, that it downloads from an unversioned URL and checks in no way: the check could
be failed on purpose to reach the path that has none (docs/06-adversarial-review.md Z112). The tests hold what it does
now: a download that does not verify ends the attempt, and swiftly is fetched and run only when the tarball could not
be had at all and the person opted in."""

import io
import json
import os
import re
import shutil
import sys
import tarfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import support  # noqa: E402

SCRIPT = os.path.join(support.ROOT, ".github", "scripts", "cloud-setup.sh")
# The system tools the script calls, linked into the scratch `bin` so that PATH can be that directory alone: whether
# `swift` is found afterwards then depends on what the script installed, not on the machine running the test.
TOOLS = "bash sh mkdir tee date grep tr awk tar gzip tail find sort uname ln chmod rm sed dirname cat cp mv head".split()

# curl [options] [-o <file>] <url>: answers by what the address is for, as $STUB_CURL says ({kind: "fail" | file to
# serve}), and writes "curl <kind>" to $STUB_LOG. A kind that is not mentioned is served a few bytes.
FAKE_CURL = r'''#!/usr/bin/env python3
import json, os, shutil, sys
arguments = sys.argv[1:]
address = arguments[-1]
if "swiftly" in address:
    kind = "swiftly"
elif address.endswith(".sig"):
    kind = "signature"
elif "all-keys" in address:
    kind = "keys"
elif address.endswith(".tar.gz"):
    kind = "tarball"
else:
    kind = "other"
probe = "-o" not in arguments
with open(os.environ["STUB_LOG"], "a", encoding="utf-8") as log:
    log.write(f"curl {kind}{' (probe)' if probe else ''} {address}\n")
answer = json.loads(os.environ.get("STUB_CURL", "{}")).get(kind, "")
if answer == "fail":
    sys.exit(22)
if not probe:
    target = arguments[arguments.index("-o") + 1]
    if answer:
        shutil.copy(answer, target)
    else:
        with open(target, "w", encoding="utf-8") as handle:
            handle.write("stand-in\n")
'''

# gpg --import … / gpg --status-fd 1 --verify <signature> <file>: reports a good signature by the key whose
# fingerprint is $STUB_SIGNER, or a bad signature when that is "bad".
FAKE_GPG = r'''#!/usr/bin/env python3
import os, sys
if "--verify" not in sys.argv:
    sys.exit(0)
signer = os.environ["STUB_SIGNER"]
if signer == "bad":
    print("[GNUPG:] BADSIG EF80A866B47A981F Swift 6.x Release Signing Key <swift-infrastructure@forums.swift.org>")
    sys.exit(1)
print("[GNUPG:] NEWSIG")
print("[GNUPG:] GOODSIG 0123456789ABCDEF A signing key")
print(f"[GNUPG:] VALIDSIG {'A' * 40} 2026-09-01 1788220800 0 4 0 1 10 00 {signer}")
'''

FAKE_SWIFT = "#!/bin/sh\necho 'Swift version 6.4.1 (a stand-in, from the release tarball)'\n"

# What swiftly does that the script relies on: `init` moves the binary into its own bin directory, and `install`
# leaves a toolchain under ~/.local/share/swiftly/toolchains.
FAKE_SWIFTLY = r"""#!/bin/sh
echo "swiftly $*" >> "$STUB_LOG"
home="$HOME/.local/share/swiftly"
case "$1" in
  init)
    mkdir -p "$home/bin" && cp "$0" "$home/bin/swiftly" && rm -f "$0"
    ;;
  install)
    mkdir -p "$home/toolchains/$2/usr/bin"
    printf '#!/bin/sh\necho "Swift version %s (a stand-in, from swiftly)"\n' "$2" > "$home/toolchains/$2/usr/bin/swift"
    chmod +x "$home/toolchains/$2/usr/bin/swift"
    ;;
esac
"""


def archive(path, member, text):
    """A .tar.gz at path holding one executable file."""
    data = text.encode()
    with tarfile.open(path, "w:gz") as tar:
        info = tarfile.TarInfo(member)
        info.size, info.mode = len(data), 0o755
        tar.addfile(info, io.BytesIO(data))
    return path


class CloudSetupTests(support.ScriptTestCase):
    def setUp(self):
        super().setUp()
        with open(SCRIPT, encoding="utf-8") as handle:
            self.pinned_key = re.search(r'^readonly SWIFT_SIGNING_KEY="([0-9A-F]{40})"$', handle.read(), re.M).group(1)
        for tool in TOOLS:
            found = shutil.which(tool)
            if found:
                os.symlink(found, os.path.join(self.bin, tool))
        self.install("curl", FAKE_CURL)
        self.install("gpg", FAKE_GPG)
        self.install("apt-get", "#!/bin/sh\nexit 0\n")
        self.install("mise", "#!/bin/sh\necho '2026.9.11 linux-x64 (a stand-in)'\n")
        self.root = self.path("machine")
        for directory in ("tmp", "var/log", "usr/local/bin", "etc/profile.d", "opt", "root", "home"):
            os.makedirs(os.path.join(self.root, directory))
        self.tarball = archive(self.path("swift.tar.gz"), "swift-6.4.1-RELEASE-ubuntu24.04/usr/bin/swift", FAKE_SWIFT)
        self.swiftly = archive(self.path("swiftly.tar.gz"), "swiftly", FAKE_SWIFTLY)
        self.write("stub.log", "")

    def setup(self, signer=None, opt_in=None, **curl):
        """Runs the script. curl: what each kind of address answers, beyond the tarball and swiftly archives."""
        answers = {"tarball": self.tarball, "swiftly": self.swiftly, **curl}
        environment = {
            "PATH": self.bin + os.pathsep + os.path.join(self.root, "usr", "local", "bin"),
            "HOME": os.path.join(self.root, "home"),
            "WATCHWORD_SETUP_TEST_ROOT": self.root,
            "STUB_LOG": self.path("stub.log"),
            "STUB_CURL": json.dumps(answers),
            "STUB_SIGNER": signer or self.pinned_key,
        }
        if opt_in is not None:
            environment["WATCHWORD_ALLOW_UNVERIFIED_SWIFTLY"] = opt_in
        os.makedirs(self.path("empty"), exist_ok=True)
        result = self.run_process([shutil.which("bash"), SCRIPT], **environment)
        # The hosting starts no session after a setup script that fails, so the script reports and exits 0.
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result.stdout

    def requests(self):
        return self.read("stub.log")

    def installed(self, *parts):
        return os.path.exists(os.path.join(self.root, *parts))

    def note(self):
        path = os.path.join(self.root, "root", ".claude", "CLAUDE.md")
        if not os.path.exists(path):
            return ""
        with open(path, encoding="utf-8") as handle:
            return handle.read()

    def assert_nothing_installed(self, output):
        self.assertFalse(self.installed("opt", "swift", "usr", "bin", "swift"))
        self.assertFalse(self.installed("home", ".local", "share", "swiftly"))
        self.assertFalse(self.installed("usr", "local", "bin", "swift"))
        self.assertIn("FAILURE: no working Swift toolchain", output)
        self.assertIn("could not install a Swift toolchain", self.note())

    def assert_swiftly_untouched(self):
        self.assertNotIn("curl swiftly", self.requests())
        self.assertNotIn("swiftly init", self.requests())
        self.assertNotIn("swiftly install", self.requests())

    def test_a_tarball_signed_by_the_pinned_key_is_installed(self):
        output = self.setup()
        self.assertIn(f"signature verified against {self.pinned_key}", output)
        self.assertIn("tarball produced a toolchain", output)
        self.assertIn("SUCCESS: swift is on PATH", output)
        self.assertTrue(self.installed("opt", "swift", "usr", "bin", "swift"))
        self.assertTrue(os.path.islink(os.path.join(self.root, "usr", "local", "bin", "swift")))
        self.assertNotIn("watchword-cloud-setup:begin", self.note())

    def test_swiftly_is_not_even_fetched_when_the_tarball_works(self):
        """Finding: the unverified installer was downloaded on every run, used or not."""
        self.setup()
        self.assert_swiftly_untouched()
        self.setup(opt_in="1")
        self.assert_swiftly_untouched()

    def test_a_failed_verification_stops_and_tries_nothing_else(self):
        """Finding: "SIGNATURE VERIFICATION FAILED" was followed by "installing via swiftly"."""
        cases = {
            "signed by another key of the bundle": {"signer": "B" * 40},
            "a bad signature": {"signer": "bad"},
            "no signature to fetch": {"signature": "fail"},
            "no key bundle to fetch": {"keys": "fail"},
        }
        for name, options in cases.items():
            for opt_in in (None, "1"):
                with self.subTest(case=name, opt_in=opt_in):
                    self.setUp()
                    output = self.setup(opt_in=opt_in, **options)
                    self.assertIn("SIGNATURE VERIFICATION FAILED; discarding the download", output)
                    self.assertIn("REFUSING to try another install method", output)
                    self.assert_swiftly_untouched()
                    self.assert_nothing_installed(output)
                    self.assertIn("possible tampering", self.note())
                    self.assertFalse(self.installed("tmp", "watchword-cloud-setup", "swift.tar.gz"))

    def test_an_unavailable_tarball_does_not_reach_swiftly_unasked(self):
        for value in (None, "", "0", "yes", "true", " 1"):
            with self.subTest(opt_in=value):
                self.setUp()
                output = self.setup(opt_in=value, tarball="fail")
                self.assertIn("tarball URL not available", output)
                self.assertIn("NOT falling back to swiftly", output)
                self.assert_swiftly_untouched()
                self.assert_nothing_installed(output)
                self.assertIn("WATCHWORD_ALLOW_UNVERIFIED_SWIFTLY=1", self.note())
                self.assertNotIn("possible tampering", self.note())

    def test_an_unavailable_tarball_reaches_swiftly_when_the_person_opted_in(self):
        output = self.setup(opt_in="1", tarball="fail")
        self.assertIn("installing via swiftly, which this script cannot verify", output)
        requests = self.requests()
        self.assertIn("curl swiftly", requests)
        self.assertIn("swiftly init --assume-yes", requests)
        self.assertIn("swiftly install 6.4.1 --assume-yes --use", requests)
        self.assertIn("swiftly produced a toolchain", output)
        self.assertIn("SUCCESS: swift is on PATH", output)
        self.assertTrue(self.installed("home", ".local", "share", "swiftly", "toolchains", "6.4.1", "usr", "bin", "swift"))
        self.assertFalse(self.installed("opt", "swift", "usr", "bin", "swift"))

    def test_a_swiftly_that_cannot_be_fetched_installs_nothing(self):
        output = self.setup(opt_in="1", tarball="fail", swiftly="fail")
        self.assertIn("swiftly download FAILED", output)
        self.assertIn("FAILURE: no working Swift toolchain", output)
        self.assertNotIn("swiftly init", self.requests())

    def test_a_toolchain_already_there_downloads_nothing(self):
        self.setup()
        self.write("stub.log", "")
        output = self.setup(tarball="fail", signer="bad")
        self.assertIn("a toolchain is already present", output)
        self.assertNotIn("curl tarball", self.requests())
        self.assert_swiftly_untouched()


if __name__ == "__main__":
    unittest.main()
