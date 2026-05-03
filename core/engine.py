import asyncio

async def run(findings, agent, interactsh_client=None):
    results = []
    for f in findings:
        result = await agent.process(f, interactsh_client)
        results.append(result)

    return results, agent.plan()