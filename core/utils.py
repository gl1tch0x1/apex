import logging
import sys
import yaml

def setup_logger(config=None):
    cfg = config or {}
    level_name = cfg.get('logging', {}).get('level', 'INFO')
    if cfg.get('log_level'):
        level_name = cfg['log_level']
    level = getattr(logging, level_name, logging.INFO)
    log_file = cfg.get('logging', {}).get('file', 'apex.log')

    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(level)
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setLevel(level)
    fh.setFormatter(fmt)
    root.addHandler(fh)
    sh = logging.StreamHandler(sys.stderr)
    sh.setLevel(level)
    sh.setFormatter(fmt)
    root.addHandler(sh)

def load_config(path):
    with open(path) as f:
        return yaml.safe_load(f)

def log(msg, level="info"):
    getattr(logging, level)(msg)