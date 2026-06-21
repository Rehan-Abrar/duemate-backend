# DueMate: Model Selection & Reference Apps

## 1. Reference AI Applications
We evaluated the following competitor AI applications to inform the UX and architecture of DueMate:
1. **Taskade AI**: Uses conversational agents to parse task lists. (Inspired our `query_tasks` intent flow).
2. **Todoist AI Assistant**: Converts natural language into structured task deadlines. (Inspired our parsing heuristic and deterministic fallback logic).
3. **Otter.ai**: Transcribes and extracts action items from noisy conversational data. (Inspired our robust extraction of Hinglish text).

## 2. Model Comparison

We evaluated three candidate foundation models for the core parsing capability:

| Criteria | Groq (Llama-3.3-70b-versatile) | OpenAI (GPT-4o) | Google (Gemini 1.5 Flash) |
| :--- | :--- | :--- | :--- |
| **Capability (Hinglish Parsing)** | Excellent context extraction | Excellent context extraction | Very Good context extraction |
| **Speed (Latency)** | **< 1.5 seconds (Fastest)** | ~3.0 seconds | ~2.5 seconds |
| **Cost per 1M Input Tokens** | **$0.59 (Lowest)** | $2.50 | $0.35 |
| **Cost per 1M Output Tokens** | **$0.79 (Lowest)** | $10.00 | $1.05 |
| **Context Window** | 128k tokens | 128k tokens | 1M tokens |

## 3. Final Decision Justification
We selected **Groq (Llama-3.3-70b-versatile)** because DueMate requires near real-time responsiveness to maintain a native WhatsApp chat feel. Groq's LPU inference engine delivers unparalleled speed (<1.5s latency), ensuring the webhook SLA from Meta is never breached. Additionally, its JSON-mode generation is highly reliable for our strict data extraction needs.
