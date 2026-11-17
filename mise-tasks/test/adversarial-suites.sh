# Sourced by `test` and `test:adversarial` (not a task: mise runs only executable files). Checks that every adversarial
# area listed in adversarial-suites.txt ran, given the test log. A `darwin:` line names a suite that only an Apple
# platform can run (it needs SQLite3, Security.framework, URLSession or CloudKit), so it is required on macOS and
# reported as skipped elsewhere, where it cannot compile. Returns non-zero if any required suite is missing.
#
# "Ran" means Swift Testing's own line for the suite: `<symbol> Suite "Adversarial: <area>" passed after <n> seconds`,
# with the whole display name between the quotes and nothing but the result symbol before it. The area's name merely
# appearing in the log is not enough: "sync log" is inside "sync log, item metadata", a test's title or output can say
# anything, and a suite that was skipped or disabled is named on a line too (docs/06-adversarial-review.md Z104;
# Tests/ScriptTests/test_audit_tasks.py). A suite that failed has already failed `swift test`.
suite_passed() { # suite_passed <log> <area>
  SUITE_LINE="Suite \"Adversarial: $2\" passed after " awk '
    BEGIN {
      want = ENVIRON["SUITE_LINE"]
      colour = sprintf("%c", 27) "\\[[0-9;]*m"
    }
    {
      line = $0
      gsub(colour, "", line)
      at = index(line, want)
      if (at == 0) next
      # A letter, digit or quote before it means the words are inside something else: a test title, a note, a log line.
      if (substr(line, 1, at - 1) ~ /[[:alnum:]"]/) next
      if (substr(line, at + length(want)) !~ /^[0-9]+(\.[0-9]+)? seconds/) next
      found = 1
    }
    END { exit !found }' "$1"
}

check_adversarial_suites() { # check_adversarial_suites <log>
  local log="$1" line suite missing=0 system
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
    suite_passed "$log" "$suite" || { echo "::error::Adversarial suite missing: $suite"; missing=1; }
  done < "$(dirname "${BASH_SOURCE[0]}")/adversarial-suites.txt"
  return "$missing"
}
