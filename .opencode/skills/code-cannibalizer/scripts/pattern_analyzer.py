#!/usr/bin/env python3
"""
Pattern Analyzer - Extract patterns from graph.json files.

Consumes the node-link format produced by explore subagents (tree-sitter WASM).
Analyzes node types, naming conventions, architecture patterns, and dependencies.

This is a HELPER script for the pattern-analyst subagent, not a standalone pipeline.
"""

import argparse
import json
import math
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field, asdict


# Per-language import resolution: determines if an import target is internal or external
IMPORT_RESOLVERS = {
    "python": lambda target, _: (
        "internal" if not any(
            target.startswith(pkg) for pkg in
            ("os", "sys", "json", "re", "math", "pathlib", "collections", "typing",
             "dataclasses", "argparse", "datetime", "time", "hashlib", "base64",
             "functools", "itertools", "operator", "string", "textwrap", "io",
             "abc", "contextlib", "copy", "enum", "struct", "unittest", "subprocess",
             "threading", "multiprocessing", "socket", "http", "urllib", "email",
             "html", "xml", "csv", "sqlite3", "logging", "warnings", "traceback",
             "inspect", "ast", "dis", "importlib", "pkgutil", "pdb", "profile",
             "timeit", "weakref", "gc", "codecs", "locale", "platform", "ctypes",
             "decimal", "fractions", "random", "statistics", "secrets", "hmac",
             "uuid", "ssl", "ftplib", "smtplib", "poplib", "imaplib", "telnetlib",
             "pickle", "shelve", "dbm", "zlib", "gzip", "bz2", "lzma", "tarfile",
             "zipfile", "shutil", "tempfile", "glob", "fnmatch", "linecache",
             "tokenize", "keyword", "token", "tabnanny", "pydoc", "doctest",
             "compileall", "py_compile", "code", "codeop", "compileall",
             "builtins", "__future__", "_thread", "types", "numbers", "cmath",
             "array", "queue", "sched", "select", "selectors", "signal", "mmap",
             "winreg", "posix", "nt", "posixpath", "ntpath", "genericpath",
             "stat", "fileinput", "filecmp", "difflib", "cmd", "shlex",
             "configparser", "tomllib", "plistlib", "uuid", "digest",
             )
        ) else "external"
    ),
    "go": lambda target, _: (
        "internal" if target.startswith(".") or target.startswith("crate/")
        else "external"
    ),
    "javascript": lambda target, _: (
        "internal" if target.startswith(".") or target.startswith("/")
        else "external"
    ),
    "typescript": lambda target, _: (
        "internal" if target.startswith(".") or target.startswith("/")
        else "external"
    ),
    "rust": lambda target, _: (
        "internal" if target.startswith("crate") or target.startswith("self")
        or target.startswith("super")
        else "external"
    ),
    "java": lambda target, _: (
        "external"  # Java imports are always fully qualified
    ),
    "csharp": lambda target, _: (
        "internal" if target.startswith(".")
        else "external"
    ),
    "ruby": lambda target, _: (
        "internal" if target.startswith(".")
        else "external"
    ),
    "php": lambda target, _: (
        "internal" if target.startswith("\\") and target.count("\\") <= 2
        else "external"
    ),
    "swift": lambda target, _: (
        "internal" if target.startswith(".")
        else "external"
    ),
    "kotlin": lambda target, _: (
        "internal" if target.startswith(".")
        else "external"
    ),
}


@dataclass
class Pattern:
    """A detected code pattern."""
    id: str
    type: str  # naming, architecture, dependency, structure
    name: str
    description: str
    frequency: int = 1
    repos: List[str] = field(default_factory=list)
    confidence: float = 0.5
    category: str = ""
    metadata: Dict = field(default_factory=dict)


@dataclass
class RepoInfo:
    """Inferred repo information from graph.json."""
    name: str
    total_nodes: int = 0
    total_edges: int = 0
    file_count: int = 0
    symbol_count: int = 0
    languages: Dict[str, int] = field(default_factory=dict)
    top_level_dirs: Set[str] = field(default_factory=set)


@dataclass
class PatternAnalysis:
    """Complete pattern analysis across repos."""
    repos: List[str] = field(default_factory=list)
    total_files: int = 0
    total_symbols: int = 0
    patterns: List[Dict] = field(default_factory=list)
    architecture: Dict = field(default_factory=dict)
    naming: Dict = field(default_factory=dict)
    dependencies: Dict = field(default_factory=dict)
    repo_details: List[Dict] = field(default_factory=list)


class GraphAnalyzer:
    """Analyze patterns from graph.json output (node-link format from explore subagents)."""

    NODE_TYPE_WEIGHTS = {
        "file": ("structure", 0.3),
        "directory": ("structure", 0.3),
        "class": ("structure", 0.8),
        "function": ("structure", 0.7),
        "method": ("structure", 0.6),
        "interface": ("structure", 0.8),
        "type": ("structure", 0.5),
        "variable": ("structure", 0.3),
        "import": ("dependency", 0.5),
        "export": ("dependency", 0.5),
        "symbol": ("structure", 0.6),
    }

    def __init__(self):
        self.repos: Dict[str, RepoInfo] = {}
        self.graphs: Dict[str, Dict] = {}
        self.patterns: Dict[str, Pattern] = {}
        self._repo_langs: Dict[str, Set[str]] = defaultdict(set)  # repo -> set of languages

    def load_graph(self, graph_path: Path) -> str:
        """Load and register a graph.json file."""
        repo_name = graph_path.parent.name if graph_path.parent.name != "graph" else graph_path.parent.parent.name

        with open(graph_path) as f:
            data = json.load(f)

        nodes = data.get("nodes", [])
        edges = data.get("edges", [])

        self.graphs[repo_name] = data

        # Build repo info
        info = RepoInfo(name=repo_name, total_nodes=len(nodes), total_edges=len(edges))

        for node in nodes:
            node_type = node.get("type", "unknown")

            if node_type == "file":
                info.file_count += 1
                ext = Path(node.get("name", "")).suffix.lower()
                if ext:
                    lang_map = {
                        ".py": "python", ".js": "javascript", ".jsx": "javascript",
                        ".ts": "typescript", ".tsx": "typescript", ".go": "go",
                        ".rs": "rust", ".java": "java", ".rb": "ruby", ".php": "php",
                        ".c": "c", ".cpp": "cpp", ".cs": "csharp", ".swift": "swift",
                        ".kt": "kotlin", ".vue": "vue", ".svelte": "svelte",
                        ".md": "markdown", ".json": "json", ".yaml": "yaml", ".yml": "yaml",
                        ".toml": "toml", ".html": "html", ".css": "css", ".scss": "scss",
                    }
                    lang = lang_map.get(ext, "other")
                    info.languages[lang] = info.languages.get(lang, 0) + 1
                    self._repo_langs[repo_name].add(lang)

                file_path = node.get("name", "")
                parts = file_path.replace("\\", "/").split("/")
                if len(parts) > 1:
                    info.top_level_dirs.add(parts[0])
            else:
                info.symbol_count += 1

        self.repos[repo_name] = info
        return repo_name

    def _add_pattern(self, type: str, name: str, description: str,
                     frequency: int = 1, repo_name: str = "",
                     category: str = "", metadata: Dict = None):
        """Register a detected pattern with per-repo tracking."""
        pid = f"{type}:{name}"
        if pid in self.patterns:
            self.patterns[pid].frequency += frequency
            if repo_name and repo_name not in self.patterns[pid].repos:
                self.patterns[pid].repos.append(repo_name)
        else:
            self.patterns[pid] = Pattern(
                id=pid, type=type, name=name, description=description,
                frequency=frequency, repos=[repo_name] if repo_name else [],
                category=category, metadata=metadata or {}
            )

    def _compute_confidence(self, pattern: Pattern) -> float:
        """Compute confidence based on repo coverage.

        Formula: min(0.95, 0.3 + (repo_count / total_repos) * 0.7)
        - 1 repo:  0.3 + (1/N)*0.7
        - all repos: 0.3 + 0.7 = 1.0 (capped at 0.95)
        """
        total = len(self.repos)
        if total == 0:
            return 0.3
        covered = len(pattern.repos)
        return min(0.95, 0.3 + (covered / total) * 0.7)

    def analyze_top_level_dirs(self):
        """Analyze top-level directory structure for architecture patterns."""
        architectures = Counter()
        repo_arch = {}  # repo -> arch type

        for repo_name, info in self.repos.items():
            dirs = set(d.lower() for d in info.top_level_dirs)

            if "src" in dirs and any(d in dirs for d in ["lib", "app", "components"]):
                arch = "modular"
            elif "lib" in dirs:
                arch = "library"
            elif "cmd" in dirs or "bin" in dirs:
                arch = "cli"
            elif "packages" in dirs or "apps" in dirs:
                arch = "monorepo"
            elif "internal" in dirs or "pkg" in dirs:
                arch = "go_standard"
            elif "api" in dirs or "routes" in dirs:
                arch = "api"
            else:
                arch = "flat"

            architectures[arch] += 1
            repo_arch[repo_name] = arch

        if architectures:
            dominant = architectures.most_common(1)[0][0]
            self._add_pattern(
                type="architecture", name=f"{dominant}_structure",
                description=f"Dominant architecture: {dominant}",
                repo_name="",  # aggregate across repos
                category="structure",
                metadata={"breakdown": dict(architectures)}
            )

    def analyze_naming(self):
        """Analyze naming conventions from node names."""
        naming = Counter()

        for repo_name, data in self.graphs.items():
            for node in data.get("nodes", []):
                name = node.get("name", "")
                node_type = node.get("type", "")
                # Only analyze symbol names (functions, classes, etc.), not file paths
                if node_type in ("class", "function", "method", "interface", "variable", "type"):
                    if "_" in name and not name[0].isupper() and not name.isupper():
                        naming["snake_case"] += 1
                    elif name[0].islower() and any(c.isupper() for c in name[1:]):
                        naming["camelCase"] += 1
                    elif name[0].isupper() and "_" not in name:
                        naming["PascalCase"] += 1
                    elif "-" in name:
                        naming["kebab-case"] += 1
                    elif name.islower():
                        # Lowercase-only names like "run", "parse", "get"
                        naming["lowercase"] += 1

        self.naming = dict(naming)

        if naming:
            dominant = naming.most_common(1)[0][0]
            self._add_pattern(
                type="naming", name=f"{dominant}_convention",
                description=f"Dominant naming convention: {dominant} ({naming[dominant]} symbols)",
                frequency=naming[dominant], repo_name="",
                category="style",
                metadata={"breakdown": dict(naming)}
            )

    def analyze_imports(self):
        """Analyze import/dependency patterns from edges using per-language resolution."""
        import_counts = Counter()
        external_imports = Counter()
        internal_imports = 0

        for repo_name, data in self.graphs.items():
            repo_langs = self._repo_langs.get(repo_name, set())
            # Determine primary language for this repo
            primary_lang = "javascript"  # default
            if repo_langs:
                lang_counts = self.repos[repo_name].languages
                if lang_counts:
                    primary_lang = max(lang_counts, key=lang_counts.get)

            resolver = IMPORT_RESOLVERS.get(primary_lang, IMPORT_RESOLVERS["javascript"])

            for edge in data.get("edges", []):
                if edge.get("type") in ("imports", "depends_on", "uses"):
                    target = edge.get("target", "")
                    result = resolver(target, repo_name)

                    if result == "external":
                        # Extract package name from target
                        pkg = target.split("/")[0].split(".")[0]
                        if pkg:
                            external_imports[pkg] += 1
                    else:
                        internal_imports += 1

                    import_counts[edge["type"]] += 1

        total = internal_imports + sum(external_imports.values())
        self.dependencies = {
            "total_relationships": total,
            "internal": internal_imports,
            "external": dict(external_imports.most_common(20)),
            "by_type": dict(import_counts),
        }

        if external_imports:
            top_libs = [lib for lib, _ in external_imports.most_common(5)]
            self._add_pattern(
                type="dependency", name="top_external_deps",
                description=f"Most common external dependencies: {', '.join(top_libs[:3])}",
                frequency=sum(external_imports.values()),
                repo_name="", category="dependencies"
            )

    def analyze_file_sizes(self):
        """Analyze file size patterns from node metadata."""
        all_lines = []
        large_files = []

        for repo_name, data in self.graphs.items():
            for node in data.get("nodes", []):
                if node.get("type") == "file":
                    lines = node.get("lines", node.get("metadata", {}).get("lines", 0))
                    if lines:
                        all_lines.append(lines)
                        if lines > 500:
                            large_files.append({
                                "file": node.get("name", ""),
                                "repo": repo_name,
                                "lines": lines
                            })

        # Sort by line count descending before truncating
        large_files.sort(key=lambda x: x["lines"], reverse=True)

        if all_lines:
            avg_lines = sum(all_lines) / len(all_lines)
            self._add_pattern(
                type="structure", name="file_sizes",
                description=f"Average file size: {avg_lines:.0f} lines (median: {sorted(all_lines)[len(all_lines)//2]})",
                frequency=len(all_lines), repo_name="",
                category="structure",
                metadata={"avg_lines": avg_lines, "total_files": len(all_lines)}
            )

        return large_files[:20]

    def analyze_languages(self):
        """Analyze language distribution across repos."""
        all_langs = Counter()
        for info in self.repos.values():
            for lang, count in info.languages.items():
                all_langs[lang] += count

        if all_langs:
            primary = all_langs.most_common(1)[0][0]
            self._add_pattern(
                type="architecture", name=f"primary_language_{primary}",
                description=f"Primary language: {primary} ({all_langs[primary]} files)",
                frequency=all_langs[primary], repo_name="",
                category="language",
                metadata={"all_languages": dict(all_langs.most_common())}
            )

    def analyze_all(self) -> PatternAnalysis:
        """Run all analyses and return results."""
        analysis = PatternAnalysis()

        for repo_name, info in self.repos.items():
            analysis.repos.append(repo_name)
            analysis.total_files += info.file_count
            analysis.total_symbols += info.symbol_count

        self.analyze_top_level_dirs()
        self.analyze_naming()
        self.analyze_imports()
        self.analyze_languages()
        large_files = self.analyze_file_sizes()

        # Compute confidence for all patterns based on repo coverage
        for pattern in self.patterns.values():
            pattern.confidence = self._compute_confidence(pattern)

        analysis.patterns = [asdict(p) for p in self.patterns.values()]
        analysis.patterns.sort(key=lambda x: (x["frequency"], x["confidence"]), reverse=True)
        analysis.architecture = {
            "patterns": [p for p in analysis.patterns if p["type"] == "architecture"],
            "large_files": large_files,
        }
        analysis.naming = self.naming
        analysis.dependencies = self.dependencies
        analysis.repo_details = [
            {
                "name": info.name,
                "files": info.file_count,
                "symbols": info.symbol_count,
                "nodes": info.total_nodes,
                "edges": info.total_edges,
                "languages": dict(Counter(info.languages).most_common(5)),
                "top_dirs": list(info.top_level_dirs),
            }
            for info in self.repos.values()
        ]

        return analysis


def check_cache(repo_url: str, workspace_dir: Path) -> Optional[Path]:
    """Check if cached graph.json exists for this repo.
    
    Args:
        repo_url: Git URL or repo name
        workspace_dir: Path to workspace directory
    
    Returns:
        Path to graph.json if cached and valid, None otherwise
    """
    # Extract repo name from URL
    repo_name = repo_url.rstrip('/').split('/')[-1].replace('.git', '')
    graph_path = workspace_dir / repo_name / ".workspace" / "graph" / "graph.json"
    
    if graph_path.exists():
        try:
            with open(graph_path) as f:
                data = json.load(f)
            if "nodes" in data and "edges" in data:
                return graph_path
        except (json.JSONDecodeError, KeyError):
            pass
    
    return None


def build_targeted_graph(matches: List[str], repo_path: Path) -> Dict:
    """Build a mini-graph from ripgrep matches + their imports.
    
    Args:
        matches: List of file paths from ripgrep search
        repo_path: Path to repository root
    
    Returns:
        Graph dict with nodes and edges
    """
    nodes = []
    edges = []
    visited_files = set()
    
    for match_file in matches:
        file_path = Path(match_file) if Path(match_file).is_absolute() else repo_path / match_file
        
        if file_path in visited_files or not file_path.exists():
            continue
        
        visited_files.add(file_path)
        
        # Add file node
        rel_path = str(file_path.relative_to(repo_path))
        nodes.append({
            "id": rel_path,
            "type": "file",
            "name": file_path.name,
            "language": file_path.suffix.lstrip('.')
        })
        
        # Parse imports (simplified - real implementation would use tree-sitter)
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            lines = content.split('\n')
            
            for line in lines:
                line = line.strip()
                
                # Python imports
                if line.startswith('import ') or line.startswith('from '):
                    parts = line.split()
                    if len(parts) >= 2:
                        target = parts[1].split('.')[0].split(',')[0]
                        edges.append({
                            "source": rel_path,
                            "target": target,
                            "type": "imports"
                        })
                
                # JavaScript/TypeScript imports
                elif line.startswith('import ') and 'from ' in line:
                    parts = line.split('from ')
                    if len(parts) >= 2:
                        target = parts[1].strip().strip("'\"").split('/')[0]
                        edges.append({
                            "source": rel_path,
                            "target": target,
                            "type": "imports"
                        })
                
                # Go imports
                elif line.startswith('"') and line.endswith('"'):
                    target = line.strip('"').split('/')[-1]
                    edges.append({
                        "source": rel_path,
                        "target": target,
                        "type": "imports"
                    })
        except Exception:
            pass
    
    return {"nodes": nodes, "edges": edges}


def main():
    parser = argparse.ArgumentParser(
        description="Analyze patterns from graph.json files (produced by explore subagents)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 pattern_analyzer.py workspace/repo1/.workspace/graph/graph.json workspace/repo2/.workspace/graph/graph.json
  python3 pattern_analyzer.py workspace/*/.workspace/graph/graph.json -o analysis.json
  python3 pattern_analyzer.py --fast workspace/repo1/.workspace/graph/graph.json
  python3 pattern_analyzer.py --full-graph ./workspace/myrepo
        """
    )
    parser.add_argument("graph_files", nargs="*", help="Paths to graph.json files or repo directories")
    parser.add_argument("-o", "--output", default="pattern_analysis.json", help="Output file")
    parser.add_argument("--fast", action="store_true", 
                        help="Fast mode: top 1-2 repos, skip simplifier")
    parser.add_argument("--full-graph", action="store_true",
                        help="Build full repo graph (default is targeted extraction)")
    parser.add_argument("--repo-url", help="Git URL for cache check")
    parser.add_argument("--workspace", default="./workspace", 
                        help="Workspace directory (default: ./workspace)")
    parser.add_argument("--target", help="Target pattern for ripgrep search")

    args = parser.parse_args()

    # Check cache if repo URL provided
    if args.repo_url:
        cached_path = check_cache(args.repo_url, Path(args.workspace))
        if cached_path:
            print(f"Cache hit: {cached_path}")
            args.graph_files = [str(cached_path)]
        else:
            print(f"No cache found for {args.repo_url}")

    # If target pattern provided, use targeted extraction
    if args.target and args.graph_files:
        import subprocess
        print(f"Targeted extraction for pattern: {args.target}")
        
        # Run ripgrep to find matches
        try:
            result = subprocess.run(
                ['rg', '-l', args.target, '--type', 'py', '--type', 'js', '--type', 'ts'],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0 and result.stdout.strip():
                matches = result.stdout.strip().split('\n')
                print(f"Found {len(matches)} matching files")
                
                # Build targeted graph from matches
                for graph_file in args.graph_files:
                    repo_path = Path(graph_file).parent.parent.parent
                    if repo_path.exists():
                        targeted_graph = build_targeted_graph(matches, repo_path)
                        
                        # Save targeted graph
                        targeted_path = repo_path / ".workspace" / "graph" / "targeted_graph.json"
                        targeted_path.parent.mkdir(parents=True, exist_ok=True)
                        
                        with open(targeted_path, 'w') as f:
                            json.dump(targeted_graph, f, indent=2)
                        
                        print(f"Targeted graph saved to: {targeted_path}")
                        args.graph_files = [str(targeted_path)]
                        break
            else:
                print("No matches found, falling back to full graph")
        except FileNotFoundError:
            print("rg not found, install ripgrep for targeted extraction")
        except subprocess.TimeoutExpired:
            print("ripgrep timed out, falling back to full graph")

    if not args.graph_files:
        print("Error: No graph files specified")
        sys.exit(1)

    analyzer = GraphAnalyzer()

    # In fast mode, limit to 2 repos
    if args.fast and len(args.graph_files) > 2:
        print(f"Fast mode: limiting to 2 repos (was {len(args.graph_files)})")
        args.graph_files = args.graph_files[:2]

    for gpath in args.graph_files:
        path = Path(gpath)
        if not path.exists():
            print(f"Warning: {gpath} not found, skipping")
            continue
        print(f"Loading: {gpath}")
        try:
            repo_name = analyzer.load_graph(path)
            info = analyzer.repos[repo_name]
            print(f"  -> {repo_name}: {info.file_count} files, {info.symbol_count} symbols, {info.total_edges} edges")
        except Exception as e:
            print(f"  Error loading {gpath}: {e}")

    if not analyzer.repos:
        print("Error: No graph files loaded")
        sys.exit(1)

    analysis = analyzer.analyze_all()

    output_data = asdict(analysis)
    with open(args.output, 'w') as f:
        json.dump(output_data, f, indent=2)

    print(f"\nAnalysis complete:")
    print(f"  Repos: {len(analysis.repos)}")
    print(f"  Files: {analysis.total_files}")
    print(f"  Symbols: {analysis.total_symbols}")
    print(f"  Patterns: {len(analysis.patterns)}")
    if analysis.architecture.get("large_files"):
        print(f"  Large files (>500 lines): {len(analysis.architecture['large_files'])}")
    print(f"  Output: {args.output}")


if __name__ == "__main__":
    main()
