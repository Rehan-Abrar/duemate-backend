# DueMate: Responsible AI & Guardrails

To ensure ethical and reliable AI usage, DueMate incorporates several guardrails and mitigations:

## 1. Hallucination Risks & Mitigation
**Risk**: The LLM may hallucinate a deadline date (e.g. interpreting "next week" as a completely wrong month) or invent course names that were not mentioned.
**Mitigations**:
- **Negative Prompting**: The system prompt explicitly commands the model: *"DO NOT invent, hallucinate, or guess dates, titles, or courses. If missing, output null."*
- **Deterministic Fallback**: If the LLM confidence is low or the API fails, the system falls back to a deterministic python `dateparser` and regex engine.
- **Human-in-the-Loop**: Any parsed output with a confidence score < 0.8 is flagged with `needs_review=True`. The user is explicitly asked to confirm or fix the details via the dashboard.

## 2. Bias Assessment
**Risk**: The AI might misunderstand local dialects, Urdu-script abbreviations (e.g., "kal", "tmr"), or university-specific slang, creating an unfair experience for certain students.
**Mitigations**:
- **Few-Shot Examples**: We injected diverse, local Hinglish slang into the prompt examples to ensure robust handling of localized phrases.
- **Keyword Pre-processing**: We map local aliases to canonical names before passing them to the model.

## 3. Data Privacy & Security
**Risk**: Student phone numbers and academic schedules being leaked.
**Mitigations**:
- **Data Isolation**: We do not use user data to train our models. Groq's API privacy policy ensures zero data retention for training.
- **Webhook Security**: All incoming WhatsApp messages are verified using `X-Hub-Signature-256` HMAC validation to prevent payload spoofing.
- **Session Auth**: Users can only view their tasks via JWT OTP authentication.

## 4. AI Disclosure
We ensure users know they are interacting with AI by:
- Including an "AI-Powered Parsing Enabled" disclaimer on the frontend dashboard.
- Using conversational agent introductions (e.g., *"I am your DueMate Assistant"*).
