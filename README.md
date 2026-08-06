# Code Cannibalizer

"Copy from one, it's theft. Copy from a thousand, it's creation."

Surgically extract proven code patterns from existing repositories and synthesize them into new projects. Works with Claude Code, OpenCode, Cursor, and any agent that supports the Agent Skills spec.

## Installation

### Option 1: skills.sh (Recommended)

```bash
npx skills add michielhdoteth/code-cannibalizer
```

### Option 2: Clone and Copy

```bash
git clone https://github.com/michielhdoteth/code-cannibalizer.git
cp -r code-cannibalizer/skills/* .agents/skills/
```

### Option 3: Git Submodule

```bash
git submodule add https://github.com/michielhdoteth/code-cannibalizer.git .agents/code-cannibalizer
```

## What It Does

- Discovers relevant open-source repos for any product/startup idea
- Maps codebases into structured knowledge graphs (graph.json + Graph.html + GRAPH_REPORT.md)
- Extracts patterns, architecture, and code from multiple sources
- Synthesizes a working, runnable application from the best patterns
- Generates a SYNTHESIS_REPORT.md documenting all sources and decisions

## Usage

Describe what you want to build and the skill will:

1. Find relevant open-source repos
2. Map their structure into knowledge graphs
3. Extract patterns and architecture
4. Build a working application
5. Document everything in SYNTHESIS_REPORT.md

### Examples

```
I want to build a real-time collaborative editor like Notion
```

```
Find open source alternatives to Stripe and build a payment integration
```

```
I'm building a CLI tool in Rust - look at clap and extract subcommand patterns
```

## Features

### Targeted Extraction (Default)
Search for specific patterns using ripgrep, then parse only matched files + imports. Full-repo mapping is opt-in.

### Cache System
Graphs persist across sessions. Skip clone+map if graph.json already exists.

### Fast Mode
Top 1-2 repos, skip code-simplifier, tests after build. Default for prototypes/spikes.

### Parallel Execution
All explore subagents run concurrently for speed.

## Workflow

```
Phase 0: Find repos that solved the problem
Phase 1: Clone and map them (graph.json + Graph.html + GRAPH_REPORT.md)
Phase 2: Extract the good parts
Phase 3: Build from proven pieces
Phase 4: Cleanup
```

## Scripts

| Script | Purpose | Run |
|--------|---------|-----|
| `scripts/pattern_analyzer.py` | Analyze patterns from graph.json | `python3 scripts/pattern_analyzer.py <paths> -o output.json [--fast] [--full-graph]` |
| `scripts/security_scanner.py` | Scan for security issues | `python3 scripts/security_scanner.py <repo_path> -o report.json [--scan-git]` |

## License

GPL-3.0 - see [LICENSE](LICENSE)
