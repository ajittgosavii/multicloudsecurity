import json
from datetime import datetime
from typing import Any, Dict

def safe_json_parse(data: str, default: Any = None) -> Any:
    """Safely parse JSON data"""
    try:
        return json.loads(data)
    except (json.JSONDecodeError, TypeError):
        return default

def format_timestamp(timestamp: str) -> str:
    """Format timestamp for display"""
    try:
        dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except (ValueError, AttributeError):
        return timestamp

def truncate_string(text: str, max_length: int = 100) -> str:
    """Truncate string to maximum length"""
    if len(text) <= max_length:
        return text
    return text[:max_length-3] + '...'