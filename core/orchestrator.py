import asyncio
import logging
import secrets
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass
from enum import Enum
import time

class AgentState(Enum):
    IDLE = "idle"
    ACTIVE = "active"
    PAUSED = "paused"
    ERROR = "error"

class CommunicationMode(Enum):
    CAVEMAN = "caveman"
    NORMAL = "normal"
    TECHNICAL = "technical"

@dataclass
class AgentContract:
    name: str
    capabilities: List[str]
    inputs: Dict[str, Any]
    outputs: Dict[str, Any]
    cost_estimate: int  # token cost

@dataclass
class Task:
    id: str
    type: str
    payload: Dict[str, Any]
    priority: int
    dependencies: List[str]
    assigned_agent: Optional[str] = None
    status: str = "pending"
    result: Optional[Any] = None
    created_at: float = None
    completed_at: Optional[float] = None

    def __post_init__(self):
        if self.created_at is None:
            self.created_at = time.time()

class CavemanCompressor:
    """Compress communication using caveman-style language"""

    @staticmethod
    def compress(message: str) -> str:
        """Compress message to caveman style"""
        # Remove articles, filler words
        words = message.split()
        compressed = []

        skip_words = {'the', 'a', 'an', 'is', 'are', 'was', 'were', 'be', 'been', 'being',
                     'have', 'has', 'had', 'do', 'does', 'did', 'will', 'would', 'could',
                     'should', 'may', 'might', 'can', 'shall', 'this', 'that', 'these', 'those'}

        for word in words:
            if word.lower() not in skip_words:
                compressed.append(word)

        return ' '.join(compressed)

    @staticmethod
    def decompress(compressed: str) -> str:
        """Add back natural language elements"""
        # This is a simple decompression - in practice would use ML
        return compressed.replace('found', 'we found').replace('scan', 'scanning')

class Orchestrator:
    """Multi-agent orchestrator using GSD workflows"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.agents: Dict[str, Any] = {}
        self.tasks: Dict[str, Task] = {}
        self.memory_temp: Dict[str, Any] = {}
        self.memory_permanent: Dict[str, Any] = {}
        self.compressor = CavemanCompressor()
        self.comm_mode = CommunicationMode.NORMAL
        self.logger = logging.getLogger(__name__)

    def register_agent(self, name: str, agent_class: Any, contract: AgentContract):
        """Register an agent with its contract"""
        self.agents[name] = {
            'class': agent_class,
            'contract': contract,
            'instance': None,
            'state': AgentState.IDLE,
            'performance': {'tasks_completed': 0, 'avg_time': 0, 'error_rate': 0}
        }
        self.logger.info(f"Agent {name} registered: {contract.capabilities}")

    async def initialize_agents(self):
        """Initialize all registered agents"""
        for name, agent_data in self.agents.items():
            try:
                agent_data['instance'] = agent_data['class'](self.config)
                agent_data['state'] = AgentState.IDLE
                self.logger.info(f"Agent {name} initialized")
            except Exception as e:
                self.logger.error(f"Failed to initialize agent {name}: {e}")
                agent_data['state'] = AgentState.ERROR

    def create_task(self, task_type: str, payload: Dict[str, Any],
                   priority: int = 1, dependencies: List[str] = None) -> str:
        """Create a new task using GSD workflow patterns"""
        task_id = f"{task_type}_{time.time_ns()}_{secrets.token_hex(4)}"
        task = Task(
            id=task_id,
            type=task_type,
            payload=payload,
            priority=priority,
            dependencies=dependencies or []
        )
        self.tasks[task_id] = task
        self.logger.info(f"Task created: {task_id} ({task_type})")
        return task_id

    async def execute_workflow(self, workflow_spec: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a GSD-style workflow"""
        workflow_name = workflow_spec.get('name', 'unnamed')
        self.logger.info(f"Starting workflow: {workflow_name}")

        # Validate required inputs
        inputs = workflow_spec.get('inputs', {})
        if not inputs.get('target'):
            raise ValueError("Target is required for workflow execution")

        # Initialize workflow context
        workflow_context: Dict[str, Any] = {
            'inputs': inputs,
            'steps': {}
        }
        completed_steps: Set[str] = set()

        # Execute steps
        results: Dict[str, Any] = {}
        steps = workflow_spec.get('steps', [])

        for step in steps:
            step_name = step.get('name')
            step_type = step.get('type')

            self.logger.info(f"Executing step: {step_name} ({step_type})")

            dependencies = step.get('dependencies', [])
            if dependencies:
                await self._wait_for_step_dependencies(dependencies, completed_steps)

            if step_type == 'task':
                # Single task execution
                task_id = self.create_task(
                    step.get('task_type'),
                    self._resolve_payload(step.get('payload', {}), workflow_context),
                    step.get('priority', 1)
                )
                result = await self.execute_task(task_id)
                results[step_name] = result
                workflow_context['steps'][step_name] = {'results': result}
                completed_steps.add(step_name)

            elif step_type == 'parallel':
                # Parallel task execution
                parallel_tasks = step.get('tasks', [])
                parallel_results = await asyncio.gather(
                    *[
                        self.execute_task(
                            self.create_task(
                                t['task_type'],
                                self._resolve_payload(t['payload'], workflow_context),
                                t.get('priority', 1),
                            )
                        )
                        for t in parallel_tasks
                    ],
                    return_exceptions=True,
                )
                errors = [r for r in parallel_results if isinstance(r, Exception)]
                for err in errors:
                    self.logger.error("Parallel subtask failed: %s", err)
                results[step_name] = parallel_results
                workflow_context['steps'][step_name] = {'results': parallel_results}
                completed_steps.add(step_name)

            elif step_type == 'conditional':
                # Conditional execution
                condition = step.get('condition', 'False')
                if self._evaluate_condition_simple(condition, workflow_context):
                    sub_result = await self.execute_workflow(step.get('then', {}))
                    results[step_name] = sub_result
                else:
                    sub_result = await self.execute_workflow(step.get('else', {}))
                    results[step_name] = sub_result
                workflow_context['steps'][step_name] = {'results': sub_result}
                completed_steps.add(step_name)

        return results

    async def execute_task(self, task_id: str) -> Any:
        """Execute a single task by assigning to appropriate agent"""
        task = self.tasks.get(task_id)
        if not task:
            raise ValueError(f"Task {task_id} not found")

        # Find suitable agent
        agent_name = self._select_agent(task)
        if not agent_name:
            raise ValueError(f"No suitable agent found for task {task.type}")

        # Assign and execute
        task.assigned_agent = agent_name
        task.status = "running"

        agent_data = self.agents[agent_name]
        agent_instance = agent_data['instance']

        try:
            agent_data['state'] = AgentState.ACTIVE

            # Compress communication if using caveman mode
            if self.comm_mode == CommunicationMode.CAVEMAN:
                task.payload = self._compress_payload(task.payload)

            start_time = time.time()
            result = await agent_instance.execute(task.payload)
            end_time = time.time()

            # Update performance metrics
            self._update_agent_performance(agent_name, end_time - start_time, success=True)

            task.status = "completed"
            task.result = result
            task.completed_at = end_time

            agent_data['state'] = AgentState.IDLE

            return result

        except Exception as e:
            self.logger.error(f"Task {task_id} failed: {e}")
            task.status = "failed"
            task.result = {"error": str(e)}
            agent_data['state'] = AgentState.ERROR
            self._update_agent_performance(agent_name, 0, success=False)
            raise

    def _select_agent(self, task: Task) -> Optional[str]:
        """Select best agent for task based on capabilities and load"""
        suitable_agents = []

        for name, agent_data in self.agents.items():
            contract = agent_data['contract']
            if task.type in contract.capabilities and agent_data['state'] != AgentState.ERROR:
                # Calculate agent score based on performance and load
                score = self._calculate_agent_score(name, task)
                suitable_agents.append((name, score))

        if not suitable_agents:
            return None

        # Return agent with highest score
        return max(suitable_agents, key=lambda x: x[1])[0]

    def _calculate_agent_score(self, agent_name: str, task: Task) -> float:
        """Calculate agent suitability score"""
        agent_data = self.agents[agent_name]
        perf = agent_data['performance']

        # Base score from performance
        base_score = 1.0 / (1.0 + perf['error_rate'])  # Lower error rate = higher score

        # Adjust for current load
        if agent_data['state'] == AgentState.ACTIVE:
            base_score *= 0.8  # Slight penalty for busy agents

        # Adjust for task priority
        if task.priority > 1:
            base_score *= 1.2  # Bonus for high priority tasks

        return base_score

    def _update_agent_performance(self, agent_name: str, execution_time: float, success: bool):
        """Update agent performance metrics"""
        agent_data = self.agents[agent_name]
        perf = agent_data['performance']

        perf['tasks_completed'] += 1

        if success:
            # Update average time
            current_avg = perf['avg_time']
            new_avg = (current_avg * (perf['tasks_completed'] - 1) + execution_time) / perf['tasks_completed']
            perf['avg_time'] = new_avg
        else:
            # Update error rate
            current_errors = perf['error_rate'] * (perf['tasks_completed'] - 1)
            perf['error_rate'] = (current_errors + 1) / perf['tasks_completed']

    async def _wait_for_step_dependencies(self, dependencies: List[str], completed_steps: Set[str]):
        """Wait until named workflow steps have finished (not raw task ids)."""
        while True:
            pending = [d for d in dependencies if d not in completed_steps]
            if not pending:
                return
            await asyncio.sleep(0.05)

    def _resolve_payload(self, payload: Any, context: Dict[str, Any]) -> Any:
        """Resolve ${...} placeholders in payloads (recursive for dict/list)."""
        if isinstance(payload, dict):
            return {k: self._resolve_payload(v, context) for k, v in payload.items()}
        if isinstance(payload, list):
            return [self._resolve_payload(item, context) for item in payload]
        if isinstance(payload, str) and payload.startswith("${") and payload.endswith("}"):
            var_path = payload[2:-1]
            return self._resolve_variable(var_path, context)
        return payload

    def _resolve_variable(self, var_path: str, context: Dict[str, Any]) -> Any:
        """Resolve a dotted path from workflow context (inputs.*, steps.*)."""
        parts = var_path.split(".")
        current: Any = context

        for part in parts:
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return None

        return current

    def _evaluate_condition_simple(self, condition: str, context: Dict[str, Any]) -> bool:
        """Safe condition evaluation for workflow steps using simpleeval (no exec/eval)."""
        if condition == "False":
            return False
        if condition == "True":
            return True
        try:
            from simpleeval import EvalWithCompoundTypes, NameNotDefined
            evaluator = EvalWithCompoundTypes(
                names={
                    "steps": context.get("steps", {}),
                    "inputs": context.get("inputs", {}),
                },
                functions={"len": len, "any": any, "all": all},
            )
            result = evaluator.eval(condition)
            return bool(result)
        except (NameNotDefined, KeyError, TypeError, ValueError) as exc:
            self.logger.debug("Condition eval failed (%s): %s", condition, exc)
            return False
        except Exception as exc:
            self.logger.warning("Unexpected condition eval error (%s): %s", condition, exc)
            return False

    _CAVEMAN_SKIP_KEYS = frozenset({
        "task_type", "target", "url", "token", "endpoints", "modules",
        "config", "findings", "exploit_chains", "context", "payload",
    })

    def _compress_payload(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Compress only safe human-readable fields; preserve URLs and structured data."""
        compressed: Dict[str, Any] = {}
        for key, value in payload.items():
            if key in self._CAVEMAN_SKIP_KEYS or self._is_uri_like(value):
                compressed[key] = value
            elif isinstance(value, str):
                compressed[key] = self.compressor.compress(value)
            else:
                compressed[key] = value
        return compressed

    @staticmethod
    def _is_uri_like(value: Any) -> bool:
        if not isinstance(value, str):
            return False
        return value.startswith(("http://", "https://", "/")) or "${" in value

    def update_memory_temp(self, key: str, value: Any):
        """Update temporary memory"""
        self.memory_temp[key] = value

    def get_memory_temp(self, key: str) -> Any:
        """Get from temporary memory"""
        return self.memory_temp.get(key)

    def promote_to_permanent_memory(self, key: str):
        """Promote temporary memory to permanent"""
        if key in self.memory_temp:
            self.memory_permanent[key] = self.memory_temp[key]
            del self.memory_temp[key]

    def get_status(self) -> Dict[str, Any]:
        """Get orchestrator status"""
        return {
            'agents': {name: {'state': data['state'].value, 'performance': data['performance']}
                      for name, data in self.agents.items()},
            'tasks': {tid: {'status': task.status, 'type': task.type, 'assigned_agent': task.assigned_agent}
                     for tid, task in self.tasks.items()},
            'memory_temp_size': len(self.memory_temp),
            'memory_permanent_size': len(self.memory_permanent),
            'communication_mode': self.comm_mode.value
        }

    def set_communication_mode(self, mode: CommunicationMode):
        """Set communication mode"""
        self.comm_mode = mode
        self.logger.info(f"Communication mode set to: {mode.value}")

    async def health_check(self) -> Dict[str, Any]:
        """Perform health check on all agents"""
        health_status = {}
        for name, agent_data in self.agents.items():
            try:
                # Ping agent
                if agent_data['instance'] and hasattr(agent_data['instance'], 'health_check'):
                    health = await agent_data['instance'].health_check()
                else:
                    health = {'status': 'unknown'}

                health_status[name] = health
            except Exception as e:
                health_status[name] = {'status': 'error', 'error': str(e)}

        return health_status
