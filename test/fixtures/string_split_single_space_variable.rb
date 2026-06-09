# Spinel known-fail: differential divergence harvested by the fuzzer.
#
# CATEGORY:  supported divergence (wrong stdout, clean exit)
#
# TRIGGER:   This minimized repro is a valid CRuby program. spinel's AOT
#            output diverges from the reference interpreter (stdout_mismatch).
#
# EXPECTED (CRuby via ruby):
#   1
#   same
#   same
#
# OBSERVED (spinel -E):
#   2
#   
#   |same
#
# Upstream-issue: TBD
# Fuzz regression 011 - String#split awk-mode only applied for literal " ", not a variable
#
# CATEGORY:  supported divergence (wrong output, clean stderr)
# SEVERITY:  high  (wrong split result)
# FOUND BY:  fuzz_spinel.rb widened generator (strings), seed 2003.
#
# TRIGGER:   Ruby's `String#split(" ")` (single ASCII space) has special
#            "awk-mode" semantics: leading/trailing whitespace is stripped and
#            runs of whitespace collapse, so "" splits to []. spinel only applies
#            this special case when the separator is a STRING LITERAL " "; when the
#            same single space comes from a VARIABLE, it falls back to plain
#            separator-split semantics, producing extra empty fields.
#
# EXPECTED (CRuby 4.0.3):
#   1
#   same
#   same
# ACTUAL (spinel -E):
#   2
#   (empty)
#   |same

left = ""
right = "same"
sep = " "
joined = left + sep + right
parts = joined.split(sep)
puts parts.length
puts parts[0]
puts parts.join("|")
