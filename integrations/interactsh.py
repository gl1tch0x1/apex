import aiohttp

class InteractshClient:
    def __init__(self, config=None):
        self.server = config.get('server', 'interactsh.com') if config else 'interactsh.com'
        self.session = None
        self.interaction_id = None
        self.base_url = f"https://{self.server}"

    async def init(self):
        if self.session is None:
            self.session = aiohttp.ClientSession()

    async def register(self):
        await self.init()
        async with self.session.post(f"{self.base_url}/register", timeout=15) as resp:
            if resp.status == 200:
                data = await resp.json()
                self.interaction_id = data.get('id')
                return self.interaction_id, data.get('secret')
        return None, None

    async def poll(self, interaction_id=None):
        await self.init()
        if interaction_id:
            self.interaction_id = interaction_id
        if not self.interaction_id:
            return []
        async with self.session.get(f"{self.base_url}/poll?id={self.interaction_id}", timeout=15) as resp:
            if resp.status == 200:
                return await resp.json()
        return []

    async def get_oast_url(self):
        interaction_id, _ = await self.register()
        if interaction_id:
            return f"https://{interaction_id}.{self.server}"
        return None

    async def close(self):
        if self.session:
            await self.session.close()
            self.session = None