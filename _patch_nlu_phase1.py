"""Patch for nlu.py: Phase 1 changes applied in one shot to handle CRLF correctly."""
import sys

path = "utils/nlu.py"
with open(path, "rb") as f:
    content = f.read().decode("utf-8")

# ────────────────────────────────────────────────────────────────────────────
# 1. Enable routing by default (false -> true)
# ────────────────────────────────────────────────────────────────────────────
OLD1 = 'return os.getenv("NLU_LLM_ROUTING_ENABLED", "false").lower() in ("1", "true", "yes")'
NEW1 = 'return os.getenv("NLU_LLM_ROUTING_ENABLED", "true").lower() in ("1", "true", "yes")'
assert OLD1 in content, "PATCH1 not found"
content = content.replace(OLD1, NEW1, 1)

# ────────────────────────────────────────────────────────────────────────────
# 2. Add "section_set" to _VALID_INTENTS
# ────────────────────────────────────────────────────────────────────────────
OLD2 = '_VALID_INTENTS = frozenset({\r\n    "schedule_query", "task_query", "save_task", "task_action",\r\n    "greeting", "help", "out_of_scope",\r\n})'
NEW2 = '_VALID_INTENTS = frozenset({\r\n    "schedule_query", "task_query", "save_task", "task_action",\r\n    "greeting", "help", "out_of_scope", "section_set",\r\n})'
assert OLD2 in content, "PATCH2 not found"
content = content.replace(OLD2, NEW2, 1)

# ────────────────────────────────────────────────────────────────────────────
# 3. Add section_set block inside _clamp_request (after out_of_scope block)
# ────────────────────────────────────────────────────────────────────────────
OLD3 = (
    '    elif intent == "out_of_scope":\r\n'
    '        oos = raw.get("out_of_scope") or {}\r\n'
    '        result["out_of_scope"] = {\r\n'
    '            "kind": _clamp(str(oos.get("kind") or "").lower(), _VALID_OOS_KINDS, None),\r\n'
    '            "topic": _sanitize_oos_topic(oos.get("topic")),\r\n'
    '        }\r\n'
    '\r\n'
    '    return result'
)
NEW3 = (
    '    elif intent == "out_of_scope":\r\n'
    '        oos = raw.get("out_of_scope") or {}\r\n'
    '        result["out_of_scope"] = {\r\n'
    '            "kind": _clamp(str(oos.get("kind") or "").lower(), _VALID_OOS_KINDS, None),\r\n'
    '            "topic": _sanitize_oos_topic(oos.get("topic")),\r\n'
    '        }\r\n'
    '\r\n'
    '    elif intent == "section_set":\r\n'
    '        sec = raw.get("section") or {}\r\n'
    '        raw_text = (sec.get("raw") or "").strip()\r\n'
    '        result["section"] = {"raw": raw_text}\r\n'
    '\r\n'
    '    return result'
)
assert OLD3 in content, "PATCH3 not found"
content = content.replace(OLD3, NEW3, 1)

# ────────────────────────────────────────────────────────────────────────────
# 4. Add section_set handling in execute() — after the task_action block
# ────────────────────────────────────────────────────────────────────────────
OLD4 = (
    '        if intent == "task_action":\r\n'
    '            result["text"] = ""\r\n'
    '            result["data"] = request.get("task_action")\r\n'
    '            return result\r\n'
    '\r\n'
    '    except Exception as exc:'
)
NEW4 = (
    '        if intent == "task_action":\r\n'
    '            result["text"] = ""\r\n'
    '            result["data"] = request.get("task_action")\r\n'
    '            return result\r\n'
    '\r\n'
    '        if intent == "section_set":\r\n'
    '            # Validation + DB write is in _handle_section_set; execute() just\r\n'
    '            # marks this as a section action so handle_message() can route it.\r\n'
    '            result["text"] = ""\r\n'
    '            result["kind"] = "section_set"\r\n'
    '            return result\r\n'
    '\r\n'
    '    except Exception as exc:'
)
assert OLD4 in content, "PATCH4 not found"
content = content.replace(OLD4, NEW4, 1)

# ────────────────────────────────────────────────────────────────────────────
# 5. Add section_set routing in handle_message() — after task_action routing
# ────────────────────────────────────────────────────────────────────────────
OLD5 = (
    '        if intent == "task_action":\r\n'
    '            return _handle_task_action(db, user_id, phone, text, request, session)\r\n'
    '\r\n'
    '        grounded = execute(request, db, user_id)'
)
NEW5 = (
    '        if intent == "task_action":\r\n'
    '            return _handle_task_action(db, user_id, phone, text, request, session)\r\n'
    '\r\n'
    '        if intent == "section_set":\r\n'
    '            return _handle_section_set(db, user_id, phone, text, request, session)\r\n'
    '\r\n'
    '        grounded = execute(request, db, user_id)'
)
assert OLD5 in content, "PATCH5 not found"
content = content.replace(OLD5, NEW5, 1)

# ────────────────────────────────────────────────────────────────────────────
# 6. Add pending_section context into _understand_user_content
# ────────────────────────────────────────────────────────────────────────────
OLD6 = (
    '    last_labels = session.get("last_task_labels") or []\r\n'
    '    if last_labels:\r\n'
    '        parts.append("Recently_listed_tasks: " + json.dumps(last_labels[:8], ensure_ascii=True))\r\n'
    '    return "\\n".join(parts)'
)
NEW6 = (
    '    last_labels = session.get("last_task_labels") or []\r\n'
    '    if last_labels:\r\n'
    '        parts.append("Recently_listed_tasks: " + json.dumps(last_labels[:8], ensure_ascii=True))\r\n'
    '    pending_section = session.get("pending_section")\r\n'
    '    if pending_section:\r\n'
    '        parts.append("Pending_section: " + json.dumps({\r\n'
    '            "awaiting_program": True,\r\n'
    '            "raw_suffix": pending_section.get("raw_suffix", ""),\r\n'
    '        }, ensure_ascii=True))\r\n'
    '    return "\\n".join(parts)'
)
assert OLD6 in content, "PATCH6 not found"
content = content.replace(OLD6, NEW6, 1)

# ────────────────────────────────────────────────────────────────────────────
# 7. Add _handle_section_set function (appended before dispatch_message)
# ────────────────────────────────────────────────────────────────────────────
SECTION_SET_FN = (
    '\r\n'
    '\r\n'
    'def _handle_section_set(db, user_id: str, phone: str, text: str, request: dict, session: dict) -> dict:\r\n'
    '    """\r\n'
    '    Execute a section_set intent: validate the raw section text and either\r\n'
    '    save it (unambiguous full section) or ask for clarification (bare/partial).\r\n'
    '    Supports multi-turn clarification via pending_section session state.\r\n'
    '    """\r\n'
    '    from utils.nlu_session import save_nlu_session, clear_pending_section  # type: ignore\r\n'
    '    from utils.academic import validate_and_resolve_section  # type: ignore\r\n'
    '\r\n'
    '    raw_section = (request.get("section") or {}).get("raw", "").strip()\r\n'
    '\r\n'
    '    # --- Multi-turn: combine pending suffix with clarification program --------\r\n'
    '    pending_sec = (session or {}).get("pending_section") or {}\r\n'
    '    raw_suffix = pending_sec.get("raw_suffix", "")\r\n'
    '    if raw_suffix and raw_section:\r\n'
    '        # The user just sent the program name in response to our clarification.\r\n'
    '        # Combine: e.g. raw_suffix="7B" + raw_section="BSCS" -> try "BSCS-7B".\r\n'
    '        combined = f"{raw_section.upper()}-{raw_suffix.upper()}"\r\n'
    '        candidate = validate_and_resolve_section(combined, db)\r\n'
    '        if candidate["status"] == "valid":\r\n'
    '            raw_section = combined\r\n'
    '        else:\r\n'
    '            # Suffix alone as the new attempt\r\n'
    '            raw_section = raw_section  # keep what the user just said; validate below\r\n'
    '\r\n'
    '    if not raw_section:\r\n'
    '        return {"action": "reply", "text": "Which section would you like to set?", "intent": "section_set"}\r\n'
    '\r\n'
    '    result_check = validate_and_resolve_section(raw_section, db)\r\n'
    '\r\n'
    '    if result_check["status"] == "ambiguous":\r\n'
    '        options = result_check.get("available") or []\r\n'
    '        suffix = result_check.get("suffix", raw_section)\r\n'
    '        options_text = " or ".join(f"*{s}*" for s in options[:5])\r\n'
    '        if not options_text:\r\n'
    '            options_text = "e.g. BSCS-7A or BSSE-7A"\r\n'
    '        # Save pending state so the next message can be combined\r\n'
    '        save_nlu_session(\r\n'
    '            db, user_id, phone,\r\n'
    '            pending_section={"raw_suffix": suffix},\r\n'
    '            pending_create=(session or {}).get("pending_create"),\r\n'
    '            pending_action=(session or {}).get("pending_action"),\r\n'
    '            last_task_ids=(session or {}).get("last_task_ids") or [],\r\n'
    '            last_task_labels=(session or {}).get("last_task_labels") or [],\r\n'
    '        )\r\n'
    '        return {\r\n'
    '            "action": "reply",\r\n'
    '            "text": f"Which program is *{suffix}* for? For example, {options_text}.",\r\n'
    '            "intent": "section_set",\r\n'
    '        }\r\n'
    '\r\n'
    '    if result_check["status"] == "not_found":\r\n'
    '        clear_pending_section(db, user_id)\r\n'
    '        return {\r\n'
    '            "action": "reply",\r\n'
    '            "text": (\r\n'
    '                f"I couldn\'t find *{raw_section}* in the current timetable. "\r\n'
    '                f"{result_check.get(\'message\', \'Please check the section name.\') }"\r\n'
    '            ),\r\n'
    '            "intent": "section_set",\r\n'
    '        }\r\n'
    '\r\n'
    '    if result_check["status"] == "valid":\r\n'
    '        section = result_check["section"]\r\n'
    '        clear_pending_section(db, user_id)\r\n'
    '        # Persist to DB\r\n'
    '        if db is not None and user_id:\r\n'
    '            db.users.update_one(\r\n'
    '                {"user_id": user_id},\r\n'
    '                {"$set": {"settings.timetable_section": section}},\r\n'
    '            )\r\n'
    '            db.user_timetables.update_one(\r\n'
    '                {"user_id": user_id},\r\n'
    '                {"$set": {"selected_section": section}},\r\n'
    '                upsert=True,\r\n'
    '            )\r\n'
    '        # Build confirmation text\r\n'
    '        try:\r\n'
    '            from utils.academic import get_published_section_context  # type: ignore\r\n'
    '            from utils.rag import retrieve_schedule_context_structured  # type: ignore\r\n'
    '            ctx = get_published_section_context(db, section)\r\n'
    '            if ctx.get("status") == "ok":\r\n'
    '                next_result = retrieve_schedule_context_structured(\r\n'
    '                    {"query_type": "next_class"}, db, user_id\r\n'
    '                )\r\n'
    '                next_text = next_result.get("text", "")\r\n'
    '                if next_text:\r\n'
    '                    return {\r\n'
    '                        "action": "reply",\r\n'
    '                        "text": f"Done! You\'re set to *{section}*. \\U0001f389\\n\\n{next_text}",\r\n'
    '                        "intent": "section_set",\r\n'
    '                    }\r\n'
    '        except Exception as exc:\r\n'
    '            logger.warning("section_set: next class lookup failed (%s)", exc)\r\n'
    '        return {\r\n'
    '            "action": "reply",\r\n'
    '            "text": f"Done! You\'re set to *{section}*. \\U0001f389",\r\n'
    '            "intent": "section_set",\r\n'
    '        }\r\n'
    '\r\n'
    '    # Fallback (should not reach here)\r\n'
    '    return {"action": "reply", "text": "Something went wrong setting your section. Please try again.", "intent": "section_set"}\r\n'
)

OLD7 = '\r\ndef dispatch_message('
assert OLD7 in content, "PATCH7 anchor not found"
content = content.replace(OLD7, SECTION_SET_FN + '\r\ndef dispatch_message(', 1)

with open(path, "wb") as f:
    f.write(content.encode("utf-8"))

print("OK: nlu.py Phase 1 patches applied")
