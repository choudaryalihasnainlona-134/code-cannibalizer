---
name: code-cannibalizer
description: Surgically extract proven code patterns from existing repositories and synthesize them into new projects. Use when the user wants to build something that already exists elsewhere, clone and analyze repos, combine code from multiple sources, learn from existing codebases, or when they mention "cannibalize", "harvest", "synthesize", "combine repos", "like X", "alternative to", "build from", or "best practices from". Finds what works, extracts it, assembles fast.
---

# Code Cannibalizer

Find what works. Extract it. Build fast.

Don't reinvent the wheel. Don't throw shit at the wall. Go find code that already solved your problem, take the good parts, assemble something new.

## Workflow

```
Phase 0: Find repos that solved the problem
Phase 1: Clone and map them
Phase 2: Extract the good parts
Phase 3: Build from proven pieces
```

## Phase 0: Find

User gives URLs? Use them.

No URLs? Search GitHub:
- "open source [domain] alternative"
- "[competitor] alternative"
- "[feature] library [language]"

Pick top 3-5 by: stars, activity, docs, language fit.

## Phase 1: Map

**Cache check**: Before cloning, check if `./workspace/<name>/.workspace/graph/graph.json` exists and is valid. If it does, skip clone+map entirely.

**Parallelization**: All explore subagents across candidate repos run concurrently. Do not serialize - spawn all at once, wait for all to complete.

Clone repos (if not cached):
```bash
git clone --filter=blob:none <url> ./workspace/<name> &
wait
```

For each repo, use the `explore` subagent to map the codebase. The explore subagent:
1. Reads README, package.json, entry points
2. Follows imports to find core modules
3. Builds `graph.json` with nodes (files, symbols) and edges (imports, calls)
4. Creates `Graph.html` interactive visualization
5. Returns: graph.json path, key modules, what this repo does well

**Validate graph.json**:
- Must have `nodes` array with objects containing `name` and `type`
- Must have `edges` array with objects containing `source`, `target`, `type`
- Reject if schema invalid

**Short-circuit**: If any explore subagent fails:
- Log the failure
- Continue with remaining repos
- Adjust confidence scores based on successful mappings only

## Phase 2: Extract

**Targeted extraction** (default):
1. Search for specific pattern/feature using ripgrep
2. Parse only matched files + their direct imports
3. Build mini-graph of relevant code only

**Full-repo graph** (opt-in): Use `--full-graph` flag to map entire repo.

Read `graph.json` files and identify:
1. **Well-designed APIs** - clean endpoints, good error handling
2. **Problem solvers** - auth, real-time, caching, pagination
3. **Good architecture** - directory structure, module boundaries
4. **Clever code** - algorithms, optimizations
5. **Working config** - env vars, feature flags

Score each by: reusability, quality, novelty, relevance.

**Attribution**: Every extracted pattern must include:
- Which repo(s) it came from
- Original file path(s)
- Confidence score based on repo coverage

Run `scripts/pattern_analyzer.py` for aggregated stats:
```bash
python3 scripts/pattern_analyzer.py <graph.json paths> -o pattern_analysis.json
```

## Phase 3: Build

Use the `coder` subagent to build from extracted components:
1. Start with best architecture from highest-quality repo
2. Plug in extracted pieces from other repos
3. Adapt to fit together
4. Write tests first (TDD) - unless fast mode
5. No bloat - only what's needed

**Fast mode** (`--fast`):
- Top 1-2 repos instead of 3-5
- Skip code-simplifier pass
- Write tests after build instead of before
- Default for prototypes/spikes
- Full pipeline reserved for production code

## Phase 4: Cleanup

After synthesis is complete:
1. Keep `workspace/` directory with graph.json files (for future cache hits)
2. Remove any temporary files
3. Keep only `SYNTHESIS_REPORT.md` and final code

## Scripts

| Script | Purpose | Run |
|--------|---------|-----|
| `scripts/pattern_analyzer.py` | Analyze patterns from graph.json | `python3 scripts/pattern_analyzer.py <paths> -o output.json [--fast] [--full-graph]` |
| `scripts/security_scanner.py` | Scan for security issues | `python3 scripts/security_scanner.py <repo_path> -o report.json [--scan-git]` |

Scripts execute deterministic work. The model runs them, doesn't load them.

## References

- `references/code_mapping_guide.md` - graph.json format and how to read it
- `references/security_checklist.md` - Security patterns to detect

Read these when needed. Don't load upfront.

## Example

**User**: "I want a tracker for my engineering team like Linear"

**Agent**:
1. Searches GitHub for "linear alternative", "issue tracker open source"
2. Finds Plane, Huly, Vikunja (top by stars + activity)
3. Clones all 3, maps each into graph.json + Graph.html
4. Extracts: Plane's kanban, Huly's real-time, Vikunja's API
5. Builds a new tracker combining the best pieces
6. Done in a day what would take months from scratch

## Output

Produce `SYNTHESIS_REPORT.md`:
- Sources and why selected
- What was extracted
- What was built
