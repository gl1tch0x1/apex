# AGENTS.md - Apex Multi-Agent System

## Agent Registry

### Core Agents

| Agent | Role | Model | Skills | Triggers |
|-------|------|-------|--------|----------|
| `apex-orchestrator` | Main task coordinator | gpt-4o-mini | planning, delegation, verification | `/apex-start`, "analyze codebase" |
| `apex-scanner` | Vulnerability scanning | claude-haiku | http, browser, payload execution | "scan target", "run modules" |
| `apex-analyzer` | LLM-based analysis | gpt-4o-mini | exploit chain, severity assessment | "analyze findings", "llm review" |
| `apex-reporter` | Report generation | claude-sonnet | json formatting, summary creation | "generate report", "export results" |
| `apex-memory` | Context management | local | compression, retrieval | "remember", "recall" |

### Subagents (Spawned by Orchestrator)

| Subagent | Purpose | Model | Output Format |
|----------|---------|-------|---------------|
| `apex-investigator` | Code/file location | haiku | caveman-compressed tables |
| `apex-builder` | Surgical edits (1-2 files) | sonnet | minimal diffs |
| `apex-reviewer` | Findings validation | haiku | one-line assessments |

## Agent Contracts

### apex-orchestrator
- **Input:** User query + context
- **Output:** Task breakdown, agent assignments, verification plan
- **Markers:** `## PLAN COMPLETE`, `## TASK ASSIGNED`, `## VERIFICATION NEEDED`

### apex-scanner
- **Input:** Target URL/API + modules list
- **Output:** Findings array with evidence
- **Markers:** `## SCAN COMPLETE`, `## VULN FOUND`, `## FALSE POSITIVE`

### apex-analyzer
- **Input:** Raw findings
- **Output:** Analyzed vulnerabilities with severity/CVSS
- **Markers:** `## ANALYSIS COMPLETE`, `## EXPLOIT CHAIN`, `## RECOMMENDATION`

### apex-reporter
- **Input:** Analyzed findings + config
- **Output:** JSON report + summary
- **Markers:** `## REPORT GENERATED`, `## EXPORT COMPLETE`

### apex-memory
- **Input:** Context to store/retrieve
- **Output:** Compressed memory blocks
- **Markers:** `## MEMORY STORED`, `## CONTEXT RETRIEVED`

## Communication Protocol

All agents use **caveman-compressed** output:
- Drop articles/filler/hedging
- Technical terms exact, code preserved
- Pattern: `[action] [target] [result]. [next]`

Example:
```
Vuln found: SQL injection @ /login. Payload: ' OR 1=1 --. Evidence: error dump. Next: analyze impact.
```

## Agent Lifecycle

1. **Spawn:** Orchestrator creates subagents via `/spawn <agent>`
2. **Execute:** Agent runs with compressed context
3. **Return:** Agent returns caveman output to orchestrator
4. **Verify:** Orchestrator validates results
5. **Clean:** Memory compressed, context updated

## Error Handling

- **Timeout:** 30s default, configurable per agent
- **Failure:** Agent returns `## ERROR: <reason>`
- **Retry:** Orchestrator respawns with adjusted context
- **Fallback:** Switch to higher model if needed

## Performance Optimization

- **Parallel Execution:** Non-dependent tasks run concurrent
- **Memory Compression:** All context compressed via caveman rules
- **Selective Triggering:** Only spawn agents when needed
- **Token Budget:** Monitor usage, switch models as needed</content>
