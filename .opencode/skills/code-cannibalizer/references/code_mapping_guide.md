# Code Mapping Guide

How to map repository structure for pattern extraction.

## Overview

Code mapping extracts the structure of a repository into a knowledge graph. This enables:
- Pattern detection across multiple repos
- Architecture analysis
- Dependency tracking
- Best practice identification

## How Mapping Works

Mapping is done by spawning `explore` subagents that parse the codebase using **tree-sitter WASM** (robust, multi-language, never explodes). No fragile regex or Python AST scripts are used.

### Per-Repo Mapping

For each cloned repo, spawn an explore subagent with instructions to build a knowledge graph:

```
task("Map <repo> structure", "explore",
  "Build a knowledge graph of ./workspace/<repo>:\n"
  "1. Walk all files (skip node_modules, .opencode, .git, build artifacts)\n"
  "2. Classify each file by type: code, doc, image, video, audio, data\n"
  "3. Parse code files with tree-sitter WASM for imports/exports/symbols\n"
  "4. Parse markdown for [[wikilinks]], frontmatter, #hashtags\n"
  "5. Build nodes (files + symbols) and edges (imports, wikilinks, defines)\n"
  "6. Output graph.json to .workspace/graph/\n"
  "Return the path to graph.json and stats: file count, languages, key modules.")
```

### Output Format

The explore subagent produces standard node-link format:

```
.workspace/graph/
├── graph.json              Raw graph data (node-link format)
├── Graph.html              Interactive visualization
└── GRAPH_REPORT.md         Summary with stats and top connections
```

The `graph.json` format:

```json
{
  "nodes": [
    {"id": "src/main.ts", "label": "src/main.ts", "type": "file", "language": "typescript", "lines": 150, "symbols": ["App"]},
    {"id": "App", "label": "App", "type": "class", "file": "src/main.ts", "language": "typescript"}
  ],
  "edges": [
    {"source": "src/main.ts", "target": "src/utils.ts", "type": "imports"},
    {"source": "App", "target": "Component", "type": "extends"}
  ]
}
```

### How to Read graph.json

The graph is a **knowledge graph** of the repository:
- **Nodes** = entities (files, classes, functions, types, variables, directories)
- **Edges** = relationships (imports, defines, inherits, calls, contains)
- Each node has a unique `id`, a `type`, and a `label`/`name`
- Files track their `language` and `lines`
- Symbols track their `file` origin

## Supported Languages

Tree-sitter WASM handles **25+ languages** with full parsing:
- JavaScript, TypeScript, JSX, TSX
- Python, Go, Rust, Java, C#, C, C++
- Ruby, PHP, Swift, Kotlin, Scala
- Dart, Zig, Lua, Solidity, Elixir
- Vue, Svelte
- Markdown, MDX (wikilinks, frontmatter)

All languages get imports, exports, and symbol extraction. No special-casing needed.

## Multi-Repo Analysis

To analyze multiple repos:

```bash
git clone --filter=blob:none <url1> ./workspace/repo1 &
git clone --filter=blob:none <url2> ./workspace/repo2 &
git clone --filter=blob:none <url3> ./workspace/repo3 &
wait
```

Then spawn explore subagents for each repo (in parallel), then run `scripts/pattern_analyzer.py` across all graph files:

```bash
python3 scripts/pattern_analyzer.py \
  ./workspace/repo1/.workspace/graph/graph.json \
  ./workspace/repo2/.workspace/graph/graph.json \
  -o pattern_analysis.json
```

## Tips

1. **Ignore noise** - Focus on src/ and lib/ directories, skip test files and generated code
2. **Large repos** - Use blobless clone (`--filter=blob:none`) for faster cloning
3. **Graph per repo** - Each repo gets its own graph.json; the analyzer combines them
4. **Tree-sitter is robust** - Never produces giant JSON or fails on edge cases like regex-based parsers do

## Targeted Extraction (Default)

When the user asks for a specific feature/pattern rather than "map the whole repo":

### 1. Search First

Use ripgrep to find relevant files:
```bash
# Search for specific pattern
rg -l "pattern" --type py --type js --type ts

# Search for function/class names
rg -l "def authenticate" --type py
rg -l "class.*Handler" --type js

# Search for specific imports
rg -l "from.*auth" --type py
```

### 2. Parse Matches

Build mini-graph from matched files + their imports:
```bash
python3 scripts/pattern_analyzer.py --target "pattern" <repo_path>
```

This will:
- Run ripgrep to find matching files
- Parse only those files + their direct imports
- Build a targeted graph.json with relevant code only

### 3. Skip Full Repo

Don't build graph.json for entire repo - just the relevant parts.

### Full-Repo Graph (Opt-in)

Use `--full-graph` flag to map entire repo:
```bash
python3 scripts/pattern_analyzer.py --full-graph <graph.json paths>
```

## Cache System

The workspace directory persists across sessions. Before cloning:
1. Check if `./workspace/<name>/.workspace/graph/graph.json` exists
2. If it does AND is valid, skip clone+map entirely
3. Reuse existing graph.json for analysis

This means:
- First run: clone + map + analyze
- Subsequent runs: skip clone, go straight to analysis
- Delete workspace/ to force fresh clone

## Parallelization

All explore subagents across candidate repos run concurrently:
```bash
# Spawn all at once
git clone --filter=blob:none <url1> ./workspace/repo1 &
git clone --filter=blob:none <url2> ./workspace/repo2 &
git clone --filter=blob:none <url3> ./workspace/repo3 &
wait

# Then spawn explore subagents for all repos simultaneously
# Don't serialize - fan out for speed
```
