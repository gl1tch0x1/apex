# BOOTSTRAP.md - Apex System Initialization

## Bootstrap Sequence

### Phase 1: Environment Setup
```bash
# Install dependencies
pip install -r requirements.txt

# Install GSD framework
npx get-shit-done-cc --global --minimal

# Install caveman compression
npx skills add JuliusBrussee/caveman

# Verify installations
python -c "import apex; print('Apex ready')"
```

### Phase 2: Agent Initialization
```bash
# Initialize orchestrator
/apex-init

# Load agent registry
python -c "from agents.registry import load_agents; load_agents()"

# Start heartbeat monitor
python -c "from core.heartbeat import start_monitor; start_monitor()"
```

### Phase 3: Memory Bootstrap
```bash
# Initialize memory system
python -c "from memory.manager import bootstrap_memory; bootstrap_memory()"

# Compress existing context
/caveman:compress MEMORY.md

# Load user preferences
python -c "from user.profile import load_profile; load_profile()"
```

### Phase 4: Tool Calibration
```bash
# Detect available tools
python -c "from tools.detector import detect_tools; detect_tools()"

# Calibrate models
/apex-calibrate-models

# Run health check
/apex-health-check
```

## Bootstrap Verification

### Checklist
- [ ] Python environment active
- [ ] All dependencies installed
- [ ] GSD framework loaded
- [ ] Caveman compression active
- [ ] Agents registered
- [ ] Memory system initialized
- [ ] Tools detected
- [ ] Heartbeat monitoring

### Health Commands
```bash
# Full system check
/apex-status

# Agent connectivity
/apex-ping-agents

# Memory integrity
/apex-verify-memory

# Tool availability
/apex-check-tools
```

## Bootstrap Recovery

### If Bootstrap Fails
1. **Clean restart:** `/apex-reset`
2. **Partial recovery:** `/apex-recover <component>`
3. **Manual override:** Edit config.yaml, restart

### Emergency Commands
```bash
# Force clean state
/apex-emergency-reset

# Debug mode bootstrap
/apex-debug-bootstrap

# Skip verification (dangerous)
/apex-force-start
```

## Configuration

### bootstrap.yaml
```yaml
phases:
  - env_setup
  - agent_init
  - memory_bootstrap
  - tool_calibration

timeouts:
  phase1: 60
  phase2: 30
  phase3: 45
  phase4: 20

retries:
  max_attempts: 3
  backoff_seconds: 5
```

## Bootstrap Metrics

- **Target Time:** < 3 minutes
- **Success Rate:** > 95%
- **Memory Usage:** < 100MB
- **Token Budget:** < 1000 tokens</content>
