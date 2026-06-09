# Spinel known-fail: differential divergence harvested by the fuzzer.
#
# CATEGORY:  build failure (codegen/analyze rejects valid CRuby)
#
# TRIGGER:   This minimized repro is a valid CRuby program. spinel's AOT
#            output diverges from the reference interpreter (build_fail).
#
# EXPECTED (CRuby via ruby):
#   2
#
# OBSERVED (spinel -E):
#   (no output)
#
# Upstream-issue: TBD
# Fuzz regression 006 - String enumerator method resolves to int 0 -> SIGSEGV
#
# CATEGORY:  crash (SIGSEGV) -- worst severity, memory-unsafe
# SEVERITY:  critical
# FOUND BY:  fuzz_spinel.rb widened generator (strings/enumerable), seeds 2001/2003/2005/2006.
#            ~9 unique sigs crash this way; ~20 more give wrong output
#            for sibling unsupported methods (scan, each_with_index, filter_map).
#
# TRIGGER:   An unsupported String/enumerator method (each_char, scan, ...) is
#            resolved to int 0; a chained call (.to_a) on that int 0 also emits 0;
#            the generated binary then dereferences the bogus value as a pointer.
#            Deterministic crash at -O0, -O2, -O3.
#
# EXPECTED (CRuby 4.0.3):
#   2
# ACTUAL (spinel -E):
#   warning: cannot resolve call to 'each_char' on string (emitting 0)
#   warning: cannot resolve call to 'to_a' on int (emitting 0)
#   Segmentation fault: 11  (exit 139)

puts "ab".each_char.to_a.length
