# Tooling (Code Browser)

Use fast local code-browser tooling to minimize token usage:

- `rg` (ripgrep): primary search tool
- `ctags` (optional): symbol navigation
- `sed`/`awk`/`nl`: context extraction with line numbers

Preferred workflow:
1) `rg` to locate candidates
2) `nl -ba` + `sed -n` to extract evidence with line numbers
3) Only expand context when needed
