# What this tree is, and what it builds against. One place, because the koinu
# pin used to live in both the Makefile and .github/workflows/ci.yml and two
# copies of a version drift.
#
# Deliberately KEY=value with no spaces: the Makefile `include`s this file and
# .github/actions/build-koinu sources it with `.`, so both read the same bytes
# rather than each parsing their own idea of the format.

PC_VERSION=0.1.0
KOINU_TAG=v0.2.2
