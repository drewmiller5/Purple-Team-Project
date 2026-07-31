from shared.memory import append_memory_entry, load_memory

# Canonical flag ids match the sigma rule filenames in wazuh-rules/ so the
# category white team assigns lines up 1:1 with what blue's detection layer
# is actually watching for.
KNOWN_FLAGS = [
    "sqli-search",
    "bruteforce-admin-login",
    "idor-documents",
    "command-injection-diagnostics",
]

_CATEGORY_KEYWORDS = {
    "sqli-search": ("sql",),
    "bruteforce-admin-login": ("brute", "admin login", "admin creds", "credential"),
    "idor-documents": ("idor", "document"),
    "command-injection-diagnostics": ("command injection", "diagnostics", "shell"),
}


def _assigned_by_white(white_memory: dict | None) -> list[str]:
    if not white_memory:
        return []
    return [
        e["assigned_flag"]
        for e in white_memory.get("entries", [])
        if e.get("phase") == "preparation" and e.get("assigned_flag") in KNOWN_FLAGS
    ]


def _found_by_red(red_memory: dict | None) -> set[str]:
    if not red_memory:
        return set()
    found = set()
    for entry in red_memory.get("entries", []):
        if not entry.get("success"):
            continue
        category = (entry.get("category") or "").lower()
        for flag, keywords in _CATEGORY_KEYWORDS.items():
            if any(keyword in category for keyword in keywords):
                found.add(flag)
    return found


def select_next_flag(white_memory: dict | None, red_memory: dict | None) -> str:
    """Picks the flag white team should focus red on next, avoiding flags
    white has already assigned or red has already successfully found. Once
    every known flag has been used at least once, round-robins to whichever
    flag white has assigned least often."""
    assigned = _assigned_by_white(white_memory)
    used = set(assigned) | _found_by_red(red_memory)

    never_used = [flag for flag in KNOWN_FLAGS if flag not in used]
    if never_used:
        return never_used[0]

    counts = {flag: assigned.count(flag) for flag in KNOWN_FLAGS}
    return min(KNOWN_FLAGS, key=lambda flag: counts[flag])


def prepare_round(white_memory_path: str, red_memory_path: str) -> str:
    """Reads white and red memory, decides the next flag, and records that
    decision in white memory. Returns the chosen flag. Never writes to the
    shared event log -- white team's preparation record lives only in its
    own memory file, same as referee's assessments stay out of the shared
    log."""
    white_memory = load_memory(white_memory_path)
    red_memory = load_memory(red_memory_path)
    flag = select_next_flag(white_memory, red_memory)
    append_memory_entry(
        white_memory_path,
        {"side": "white", "phase": "preparation", "assigned_flag": flag},
    )
    return flag
