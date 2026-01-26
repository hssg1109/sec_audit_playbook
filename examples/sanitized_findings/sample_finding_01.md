# Sample Finding: Reflected XSS

**Severity**: medium

## Description
Input is reflected without encoding on the search results page.

## Evidence
See `examples/sanitized_evidence/sample_request_response.txt`.

## Recommendation
Apply output encoding and validate input.
