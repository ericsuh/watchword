# Sourced by `test` and `test:adversarial` (not a task: mise runs only executable files). Checks that every adversarial
# area listed in adversarial-suites.txt ran, given the test log. A `darwin:` line names a suite that only an Apple
# platform can run (it needs SQLite3, Security.framework, URLSession or CloudKit), so it is required on macOS and
# reported as skipped elsewhere, where it cannot compile. Returns non-zero if any required suite is missing.
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
    grep -Fq "$suite" "$log" || { echo "::error::Adversarial suite missing: $suite"; missing=1; }
  done < "$(dirname "${BASH_SOURCE[0]}")/adversarial-suites.txt"
  return "$missing"
}
