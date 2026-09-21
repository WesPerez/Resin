"""Non-secret operational limits shared by the scheduled subscription tasks."""
import json
from pathlib import Path

PATH = Path('/etc/server-scheduled-tasks/proxy-subscription-settings.json')
DEFAULTS = {'site_ttl_minutes': 90, 'rotation_ttl_minutes': 60, 'max_page_load_ms': 18000,
            'network_cooldown_minutes': 30, 'challenge_quarantine_hours': 24,
            'rotation_batch_size': 8, 'client_probe_timeout_seconds': 10,
            'subscription_timeout_seconds': 15}
LIMITS = {'site_ttl_minutes': (45, 90), 'rotation_ttl_minutes': (30, 60),
          'max_page_load_ms': (3000, 18000), 'network_cooldown_minutes': (30, 120),
          'challenge_quarantine_hours': (24, 168), 'rotation_batch_size': (1, 8),
          'client_probe_timeout_seconds': (3, 10), 'subscription_timeout_seconds': (5, 15)}


def load(path=PATH):
    configured = json.loads(path.read_text()) if path.exists() else {}
    if not isinstance(configured, dict) or set(configured) - set(DEFAULTS):
        raise ValueError('Invalid subscription operating settings')
    values = {**DEFAULTS, **configured}
    if any(type(values[k]) is not int or not low <= values[k] <= high for k, (low, high) in LIMITS.items()):
        raise ValueError('Subscription settings exceed verified resource and quality limits')
    return values
