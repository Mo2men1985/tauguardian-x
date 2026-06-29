# Task Definitions

Task specs in this repository are synthetic benchmark tasks. They are intended
to exercise coding-agent behavior and security-review heuristics.

Task specs should:

- use synthetic users, accounts, tokens, and records;
- avoid real personal, client, or operational data;
- avoid real credentials or credential-like examples;
- describe security expectations clearly;
- remain small enough for unit tests and review.

If a task requires secret handling, it should pass secret material as function
arguments or environment variables in test code using synthetic placeholders.
Never hardcode real secrets in task specs or implementations.
