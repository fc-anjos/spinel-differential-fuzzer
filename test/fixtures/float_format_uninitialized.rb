# Spinel known-fail: differential divergence harvested by the fuzzer.
#
# CATEGORY:  supported divergence (wrong stdout, clean exit)
#
# TRIGGER:   This minimized repro is a valid CRuby program. spinel's AOT
#            output diverges from the reference interpreter (stdout_mismatch).
#
# EXPECTED (CRuby via ruby):
#   93
#
# OBSERVED (spinel -E):
#   643
#
# Upstream-issue: TBD
# Fuzz regression 010 - float format specifier reads uninitialized memory
#
# CATEGORY:  supported divergence (wrong output from a memory-safety defect)
# SEVERITY:  high  (reads uninitialized stack memory; value is garbage)
# FOUND BY:  fuzz_spinel.rb widened generator (strings/numeric), seed 2005.
#
# TRIGGER:   A float conversion specifier (`%g`, `%e`, `%f`) in `String#%` /
#            `format(...)` does not correctly read the float operand; the generated
#            code reads uninitialized memory instead of the supplied float.
#            DETERMINISTIC here (643 vs 93 across O0/O2/O3) -- the value is wrong
#            but stable; the earlier "differs by opt level" claim did NOT reproduce
#            on this host (both %g and %e are opt-stable), so this is a plain
#            stdout-mismatch, not an opt-level divergence.
#
# EXPECTED (CRuby 4.0.3):
#   93        # "%g" % [-0.0] => "-0", bytes 45+48 = 93
# ACTUAL (spinel -E):
#   643       # spinel renders garbage like "5.21502e-310"
#
# SIBLING (same root cause): ("%e" % [1.5]).bytes.sum -> 691 (spinel) vs 628 (CRuby).

puts (("%g" % [-0.0]).bytes.sum)
