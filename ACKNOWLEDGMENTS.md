# Acknowledgments

This project was built for the `alexykn` jevscan workflow and draws on Alexander
Knott's MIT-licensed [jevscan](https://github.com/alexykn/jevscan): explicit shared
state and target binding, independent typed Jev questions, preservation of provider
probability values, evidence-aware warning policy, and plain ANSI terminal output.
The original copyright notice is retained in LICENSE alongside the new project.

The implementation is a focused sibling, not a vendored copy of jevscan's parser,
calibration system, compaction engine or source-code rules. It does not inherit
jevscan's evaluation results. Process-classification calibration is a separate,
still-open validation task.

TypeSafe/Jev is an external service. This project is not an official TypeSafe or
psutil product and makes no claim of endorsement. Dependency licenses remain with
their respective authors.
