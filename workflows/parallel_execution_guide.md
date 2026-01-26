# Parallel Execution Guide

- Start with Discovery tasks (1-1, 1-2) in parallel.
- Run External Requests (2-1, 2-2) in parallel after Discovery.
- Run Static Analysis task 3-1 first, then run 3-2/3-3/3-4 in parallel.
- Dynamic Testing (4-1, 4-2) can run in parallel after Discovery.
- Dependency Scan (5) can run in parallel after Discovery.
- Reporting runs after Static, Dynamic, and Dependency Scan complete.
