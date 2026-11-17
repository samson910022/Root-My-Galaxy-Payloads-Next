# pa3q-S938NKSUACZF1 target profile

This directory contains the firmware-specific profile for SM-S938N build
`S938NKSUACZF1` and kernel
`6.6.98-android15-8-pd6ff1cd-abogkiS938NKSUACZF1-4k`.

The profile defines the compact waiter layout, runtime KASLR inputs, physical
memory geometry, task-bank selection, pipe layout, and required kernel symbol
locations for this build.

No dated or hash-bound hardware validation evidence exists in this repository
for this profile; see `docs/SM-S938N-S938NKSUACZF1.md` for the recorded
validation status and for the claims rejected from closed upstream PR #1. The
profile is specific to S938NKSUACZF1 and must not be selected for any other
firmware build without a separate compatibility check.
