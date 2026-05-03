# HEARTBEAT.md - Apex System Monitoring

## Heartbeat System

### Core Metrics
- **Agent Health:** Response time < 5s
- **Memory Usage:** < 80% of available
- **Token Budget:** > 20% remaining
- **Error Rate:** < 5% per hour

### Heartbeat Checks

#### Agent Pulse
```python
# Check agent responsiveness
for agent in agents:
    response = ping_agent(agent)
    if response.delay > 5000:
        alert(f"Agent {agent} slow: {response.delay}ms")
```

#### Memory Pulse
```python
# Monitor memory pressure
usage = get_memory_usage()
if usage > 0.8:
    compress_memory()
    alert("Memory compressed")
```

#### Token Pulse
```python
# Track token consumption
budget = get_token_budget()
if budget < 0.2:
    switch_to_cheaper_model()
    alert("Switched to cost-effective model")
```

### Alert Levels

| Level | Condition | Action |
|-------|-----------|--------|
| INFO | Normal operation | Log only |
| WARN | Performance degradation | Alert user |
| ERROR | System instability | Auto-recover |
| CRITICAL | System failure | Emergency shutdown |

### Recovery Protocols

#### WARN Level
1. Compress context
2. Switch to lighter model
3. Reduce concurrency

#### ERROR Level
1. Pause non-critical agents
2. Force memory cleanup
3. Restart failed components

#### CRITICAL Level
1. Save state to disk
2. Graceful shutdown
3. Send emergency alert

### Heartbeat Dashboard

```
/apex-heartbeat
├── Agents: 5/5 healthy
├── Memory: 45% used
├── Tokens: 75% remaining
├── Errors: 0.2% rate
└── Uptime: 2h 15m
```

### Monitoring Commands

```bash
# Real-time dashboard
/apex-monitor

# Historical metrics
/apex-metrics --since 1h

# Alert history
/apex-alerts --last 10

# Performance report
/apex-perf-report
```

### Health Endpoints

- `/health/agents` - Agent status
- `/health/memory` - Memory metrics
- `/health/tokens` - Token usage
- `/health/system` - Overall health

### Auto-Healing

#### Self-Diagnosis
```python
def diagnose_issue():
    if agent_unresponsive():
        return "agent_failure"
    if memory_full():
        return "memory_pressure"
    if token_exhausted():
        return "budget_exceeded"
    return "unknown"
```

#### Auto-Fixes
```python
def apply_fix(issue):
    if issue == "agent_failure":
        restart_agent()
    elif issue == "memory_pressure":
        compress_and_cleanup()
    elif issue == "budget_exceeded":
        switch_model("haiku")
```

### Logging

#### Heartbeat Logs
```
[2024-01-15 10:30:00] HEARTBEAT: All systems normal
[2024-01-15 10:35:00] WARN: Memory usage at 75%
[2024-01-15 10:36:00] INFO: Memory compressed, usage now 45%
```

#### Alert Logs
```
[2024-01-15 10:35:00] ALERT: Memory pressure detected
[2024-01-15 10:35:05] RECOVERY: Memory compression applied
```

### Configuration

#### heartbeat.yaml
```yaml
intervals:
  agent_check: 30  # seconds
  memory_check: 60
  token_check: 300

thresholds:
  response_time: 5000  # ms
  memory_usage: 0.8    # 80%
  token_budget: 0.2    # 20%

alerts:
  email: user@example.com
  slack: #webhook_url
  discord: #webhook_url
```

### Emergency Procedures

#### System Halt
```bash
/apex-emergency-stop
# Saves state, stops all agents, preserves memory
```

#### System Resume
```bash
/apex-resume
# Loads saved state, restarts agents, verifies integrity
```

#### Data Recovery
```bash
/apex-recover-data
# Rebuilds from backups, validates consistency
```</content>
