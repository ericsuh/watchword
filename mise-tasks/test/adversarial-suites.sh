# Sourced by `test` and `test:adversarial` (not a task: mise runs only executable files). Checks that every adversarial
# area listed in adversarial-suites.txt ran, given the test log. A `darwin:` line names a suite that only an Apple
# platform can run (it needs SQLite3, Security.framework, URLSession or CloudKit), so it is required on macOS and
# reported as skipped elsewhere, where it cannot compile. Returns non-zero if any required suite is missing.
#
# "Ran" means Swift Testing's own line for the suite, once: `<symbol> Suite "Adversarial: <area>" passed after <n>
# seconds`, with the whole display name between the quotes and nothing but the result symbol before it. The area's name
# merely appearing in the log is not enough: "sync log" is inside "sync log, item metadata", and a test's title or
# output can say anything (docs/06-adversarial-review.md Z104; Tests/ScriptTests/test_audit_tasks.py). And a pass is
# not believed beside a contradiction: a line anywhere that reports the suite skipped or failed, or the words of its
# pass on more than one line, fails the area, because one of the lines is then not Swift Testing's and this cannot
# tell which (Z112). What it cannot do is tell a line Swift Testing wrote from the same line printed by a test, when
# that is the only one: whoever can add a test can forge the log, which is inherent in reading a log, and review of
# the tests is what answers it.
#
# awk reads the log as bytes (`LC_ALL=C`). The result symbol is not ASCII, and a byte-oriented awk classes its bytes
# by the caller's locale: in a Latin-1 locale the first byte of the tick is a letter, and every genuine pass was
# reported missing (Z110).
suite_result() { # suite_result <log> <area>: 0 passed, once; 1 no pass; 2 reported skipped or failed; 3 passed twice
  SUITE_NAME="Suite \"Adversarial: $2\"" LC_ALL=C awk '
    BEGIN {
      name = ENVIRON["SUITE_NAME"]
      want = name " passed after "
      colour = sprintf("%c", 27) "\\[[0-9;]*m"
    }
    {
      line = $0
      gsub(colour, "", line)
      if (index(line, name " skipped") || index(line, name " failed")) contradicted = 1
      at = index(line, want)
      if (at == 0) next
      said += 1
      # A letter, digit or quote before it means the words are inside something else: a test title, a note, a log line.
      if (substr(line, 1, at - 1) ~ /[[:alnum:]"]/) next
      if (substr(line, at + length(want)) !~ /^[0-9]+(\.[0-9]+)? seconds/) next
      found += 1
    }
    END {
      if (contradicted) exit 2
      if (said > 1) exit 3
      exit (found == 1) ? 0 : 1
    }' "$1"
}

# For `test:adversarial`: no test of the security suite may be skipped. A suite whose every test is disabled is
# still reported as passed, so the suite lines above do not see it; Swift Testing reports each such test as
# `<symbol> Test <name> skipped`, with the reason if one was given. (The form is from Swift Testing's source, not
# from a run: no test here is disabled to look at.) A title that merely ends in the word is not that line: the name
# before it must close with `"` or `)`.
no_skipped_tests() { # no_skipped_tests <log>
  local skipped
  skipped=$(LC_ALL=C awk '
    BEGIN { colour = sprintf("%c", 27) "\\[[0-9;]*m" }
    {
      line = $0
      gsub(colour, "", line)
      if (line ~ /^[^[:alnum:]"]*Test .*[")] skipped(\.|: ".*")$/) print line
    }' "$1")
  if [ -n "$skipped" ]; then
    echo "::error::An adversarial test was skipped; the security suite runs whole or the run fails:"
    echo "$skipped"
    return 1
  fi
}

check_adversarial_suites() { # check_adversarial_suites <log>
  local log="$1" line suite missing=0 system result
  system=$(uname -s)
  while IFS= read -r line; do
    case "$line" in "" | "#"*) continue ;; esac
    suite="$line"
    if [ "${line#darwin: }" != "$line" ]; then
      suite="${line#darwin: }"
      if [ "$system" != Darwin ]; then
        echo "Adversarial suite not required on $system (Apple platforms only): $suite"
        continue
      fi
    fi
    result=0
    suite_result "$log" "$suite" || result=$?
    case "$result" in
      0) ;;
      2) echo "::error::Adversarial suite skipped or failed: $suite"; missing=1 ;;
      3) echo "::error::Adversarial suite reported as passed more than once: $suite"; missing=1 ;;
      *) echo "::error::Adversarial suite missing: $suite"; missing=1 ;;
    esac
  done < "$(dirname "${BASH_SOURCE[0]}")/adversarial-suites.txt"
  return "$missing"
}
