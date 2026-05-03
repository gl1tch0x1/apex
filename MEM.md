# MEM.md - Temporary Memory System

## Temporary Memory (MEM.md)

### Purpose
Short-term context storage for active sessions. Compressed, ephemeral, automatically cleaned.

### Structure
```
MEM.md
├── Session Context
├── Active Tasks
├── Temporary Results
└── Working State
```

### Memory Lifecycle

#### Creation
- **Trigger:** New session starts
- **Content:** User query, initial context
- **Compression:** Automatic caveman compression

#### Updates
- **Frequency:** After each agent interaction
- **Method:** Append compressed results
- **Cleanup:** Remove obsolete entries

#### Cleanup
- **Trigger:** Session end or memory pressure
- **Method:** Compress to MEMORY.md or discard
- **Retention:** Critical context only

### Content Types

#### Session Context
```
Session: scan-web-app
User: Analyze https://example.com
Modules: sql_injection, xss, auth
Start: 2024-01-15T10:00:00Z
Status: active
```

#### Active Tasks
```
Tasks:
- scanner: running on target
- analyzer: waiting for results
- reporter: pending
```

#### Temporary Results
```
Results:
- vuln_001: SQL injection found
- vuln_002: XSS potential
- false_pos_001: dismissed
```

#### Working State
```
State:
- current_module: sql_injection
- progress: 45%
- next_action: analyze_findings
```

### Compression Rules

#### Caveman Compression
- Drop articles, filler words
- Keep technical terms exact
- Use fragments when possible
- Preserve code/URLs/paths

#### Example
**Before:**
```
The scanner has found a potential SQL injection vulnerability in the login form at /login.php. The payload used was ' OR 1=1 -- and it returned database error information.
```

**After:**
```
SQL injection found @ /login.php. Payload: ' OR 1=1 --. Result: DB error dump.
```

#### Token Savings
- **Target:** 60-75% reduction
- **Method:** Semantic compression
- **Verification:** Token counting

### Memory Management

#### Size Limits
- **Max Size:** 10KB per session
- **Compression Trigger:** 5KB reached
- **Cleanup Trigger:** 8KB reached

#### Priority Levels
1. **Critical:** Current task state
2. **High:** Active results
3. **Medium:** Recent context
4. **Low:** Historical data

#### Auto-Cleanup
```python
def cleanup_memory():
    if size > max_size:
        compress_low_priority()
        if still_over:
            archive_to_memory_md()
            reset_temp_memory()
```

### Integration Points

#### With Agents
- **Input:** Agents read from MEM.md
- **Output:** Agents append to MEM.md
- **Format:** Caveman-compressed

#### With Orchestrator
- **Planning:** Uses MEM.md for context
- **Delegation:** Updates task status
- **Verification:** Checks completion

#### With User
- **Display:** Summarized view
- **Export:** On demand
- **Clear:** Manual trigger

### Error Handling

#### Memory Corruption
```python
def repair_memory():
    try:
        validate_format()
    except CorruptionError:
        restore_from_backup()
        alert_user("Memory repaired")
```

#### Out of Memory
```python
def handle_oom():
    compress_aggressively()
    if still_oom:
        pause_non_critical()
        alert_user("Memory optimized")
```

### Monitoring

#### Metrics
- **Size:** Current memory usage
- **Compression Ratio:** Tokens saved
- **Access Frequency:** Read/write operations
- **Cleanup Events:** Automatic maintenance

#### Alerts
- **Warning:** Approaching size limit
- **Error:** Compression failed
- **Critical:** Memory corruption detected

### Backup and Recovery

#### Automatic Backup
- **Trigger:** Before major operations
- **Location:** .apex/backups/mem_{timestamp}.md
- **Retention:** Last 5 backups

#### Recovery Process
1. Detect corruption
2. Load last good backup
3. Reconstruct from MEMORY.md
4. Resume operations

### Security Considerations

#### Sensitive Data
- **Detection:** Scan for secrets
- **Handling:** Encrypt or exclude
- **Alert:** Notify user of exposure risk

#### Access Control
- **Read:** Agents can read session data
- **Write:** Only orchestrator and active agents
- **Clear:** User command only

### Performance Optimization

#### Lazy Loading
- Load only active session data
- Cache compressed versions
- Prefetch related context

#### Parallel Access
- Thread-safe operations
- Non-blocking reads
- Atomic writes

### User Commands

```bash
# View current memory
/apex-mem-show

# Clear temporary memory
/apex-mem-clear

# Compress memory
/apex-mem-compress

# Export memory
/apex-mem-export
```

### Integration with MEMORY.md

#### Promotion Path
```
MEM.md (temp) → compress → MEMORY.md (permanent)
```

#### Synchronization
- **Push:** Important data moves to permanent
- **Pull:** Historical context loads to temp
- **Merge:** Resolve conflicts automatically</content>
