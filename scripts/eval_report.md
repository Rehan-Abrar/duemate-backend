# DueMate Evaluation Harness Report

> Generated: 2026-06-22 00:01 UTC

## 📊 Summary

| Metric | Value |
|:---|:---|
| **Overall Pass Rate** | 19/24 (79%) |
| Task Type Accuracy | 22/24 (91%) |
| Course Extraction Accuracy | 22/24 (91%) |
| Due Date Extraction Accuracy | 23/24 (95%) |
| Avg Latency | 986 ms |
| Avg Confidence Score | 0.94 |
| Parse Methods | {"groq": 24} |

## 🧪 Test Case Results

| # | Pass | Message | Type ✓ | Course ✓ | Date ✓ | Confidence | Latency | Method |
|---|:---:|---|:---:|:---:|:---:|:---:|---:|---|
| 1 | ❌ | `PDC assignment submit karna hai friday tak` | ✅ | ⚠️ | ✅ | 1.0 | 727.5ms | groq |
| 2 | ✅ | `Advanced DBMS assignment 3 due on 12 July 2026` | ✅ | ✅ | ✅ | 1.0 | 2766.0ms | groq |
| 3 | ✅ | `guys cn ka project 30 June 2026 tak jama karwana hai please note karlo` | ✅ | ✅ | ✅ | 1.0 | 428.4ms | groq |
| 4 | ✅ | `AI driven SE project due on 25 June 2026 before 5PM` | ✅ | ✅ | ✅ | 1.0 | 1098.2ms | groq |
| 5 | ✅ | `Submit Theory of Automata assignment before Monday midnight` | ✅ | ✅ | ✅ | 0.9 | 486.4ms | groq |
| 6 | ✅ | `Here is complete assignment 4, student need to submit on 22 June 2026 …` | ✅ | ✅ | ✅ | 0.85 | 1914.2ms | groq |
| 7 | ✅ | `entrepreneurship lab report due next wednesday` | ✅ | ✅ | ✅ | 0.9 | 978.1ms | groq |
| 8 | ✅ | `adbms lab assignment submit karein 15 july tak` | ✅ | ✅ | ✅ | 1.0 | 796.3ms | groq |
| 9 | ✅ | `Computer Networks assignment #2 is due on July 5, 11:59PM` | ✅ | ✅ | ✅ | 1.0 | 742.9ms | groq |
| 10 | ✅ | `Problem Solving 3 homework due kal` | ✅ | ✅ | ✅ | 0.85 | 516.1ms | groq |
| 11 | ✅ | `kal TOA ka quiz hai chapter 3 aur 4 se` | ✅ | ✅ | ✅ | 1.0 | 683.2ms | groq |
| 12 | ❌ | `Sir said next week AI class quiz related to neural networks and backpr…` | ✅ | ✅ | ❌ | 1.0 | 2063.7ms | groq |
| 13 | ❌ | `Computer Networks Lab Exam 21 June Friday 2-5pm` | ❌ | ✅ | ✅ | 1.0 | 938.3ms | groq |
| 14 | ❌ | `PDC quiz tomorrow morning 9am chapter 5` | ✅ | ⚠️ | ✅ | 1.0 | 922.5ms | groq |
| 15 | ✅ | `dbms quiz on ER diagrams next monday` | ✅ | ✅ | ✅ | 1.0 | 1017.8ms | groq |
| 16 | ✅ | `quiz of automata will be on Monday` | ✅ | ✅ | ✅ | 0.9 | 898.0ms | groq |
| 17 | ✅ | `entrepreneurship quiz hai kal slides 10 se 20 tak` | ✅ | ✅ | ✅ | 1.0 | 580.9ms | groq |
| 18 | ✅ | `AI driven software development quiz next class on transformers` | ✅ | ✅ | ✅ | 0.55 | 1916.7ms | groq |
| 19 | ✅ | `Assignment 3 Deadline: tomorrow 12PM` | ✅ | ✅ | ✅ | 0.85 | 312.6ms | groq |
| 20 | ✅ | `Submit assignment before 2PM on 25 June 2026` | ✅ | ✅ | ✅ | 0.85 | 1107.7ms | groq |
| 21 | ✅ | `tmr ADBMS test hai chapter 2 se` | ✅ | ✅ | ✅ | 1.0 | 720.3ms | groq |
| 22 | ✅ | `quiz kal hai parha lo` | ✅ | ✅ | ✅ | 0.8 | 856.9ms | groq |
| 23 | ❌ | `CN lab viva on friday` | ❌ | ✅ | ✅ | 1.0 | 547.0ms | groq |
| 24 | ✅ | `AISD project milestone 2 due 30 june` | ✅ | ✅ | ✅ | 1.0 | 639.5ms | groq |

## 📋 Detailed Results

### [FAIL] #1: `PDC assignment submit karna hai friday tak`
- **Type**: `assignment`  |  **Course**: `Parallel & Distributed Computing`  |  **Due Date**: `2026-06-26 18:59 UTC`
- **Confidence**: 1.0  |  **Needs Review**: False  |  **Latency**: 727.5ms

### [PASS] #2: `Advanced DBMS assignment 3 due on 12 July 2026`
- **Type**: `assignment`  |  **Course**: `Advanced DBMS`  |  **Due Date**: `2026-07-12 18:59 UTC`
- **Confidence**: 1.0  |  **Needs Review**: False  |  **Latency**: 2766.0ms

### [PASS] #3: `guys cn ka project 30 June 2026 tak jama karwana hai please note karlo`
- **Type**: `assignment`  |  **Course**: `Computer Networks`  |  **Due Date**: `2026-06-30 18:59 UTC`
- **Confidence**: 1.0  |  **Needs Review**: False  |  **Latency**: 428.4ms

### [PASS] #4: `AI driven SE project due on 25 June 2026 before 5PM`
- **Type**: `assignment`  |  **Course**: `AI-Driven Software Development`  |  **Due Date**: `2026-06-25 12:00 UTC`
- **Confidence**: 1.0  |  **Needs Review**: False  |  **Latency**: 1098.2ms

### [PASS] #5: `Submit Theory of Automata assignment before Monday midnight`
- **Type**: `assignment`  |  **Course**: `Theory of Automata`  |  **Due Date**: `2026-06-29 18:59 UTC`
- **Confidence**: 0.9  |  **Needs Review**: False  |  **Latency**: 486.4ms

### [PASS] #6: `Here is complete assignment 4, student need to submit on 22 June 2026 …`
- **Type**: `assignment`  |  **Course**: `(none)`  |  **Due Date**: `2026-06-22 09:00 UTC`
- **Confidence**: 0.85  |  **Needs Review**: False  |  **Latency**: 1914.2ms

### [PASS] #7: `entrepreneurship lab report due next wednesday`
- **Type**: `assignment`  |  **Course**: `Technology Entrepreneurship`  |  **Due Date**: `2026-06-24 18:59 UTC`
- **Confidence**: 0.9  |  **Needs Review**: False  |  **Latency**: 978.1ms

### [PASS] #8: `adbms lab assignment submit karein 15 july tak`
- **Type**: `assignment`  |  **Course**: `Advanced DBMS`  |  **Due Date**: `2026-07-15 18:59 UTC`
- **Confidence**: 1.0  |  **Needs Review**: False  |  **Latency**: 796.3ms

### [PASS] #9: `Computer Networks assignment #2 is due on July 5, 11:59PM`
- **Type**: `assignment`  |  **Course**: `Computer Networks`  |  **Due Date**: `2026-07-05 18:59 UTC`
- **Confidence**: 1.0  |  **Needs Review**: False  |  **Latency**: 742.9ms

### [PASS] #10: `Problem Solving 3 homework due kal`
- **Type**: `assignment`  |  **Course**: `(none)`  |  **Due Date**: `2026-06-23 18:59 UTC`
- **Confidence**: 0.85  |  **Needs Review**: False  |  **Latency**: 516.1ms

### [PASS] #11: `kal TOA ka quiz hai chapter 3 aur 4 se`
- **Type**: `quiz`  |  **Course**: `Theory of Automata`  |  **Due Date**: `2026-06-23 18:59 UTC`
- **Confidence**: 1.0  |  **Needs Review**: False  |  **Latency**: 683.2ms

### [FAIL] #12: `Sir said next week AI class quiz related to neural networks and backpr…`
- **Type**: `quiz`  |  **Course**: `AI-Driven Software Development`  |  **Due Date**: `2026-06-28 18:59 UTC`
- **Confidence**: 1.0  |  **Needs Review**: False  |  **Latency**: 2063.7ms

### [FAIL] #13: `Computer Networks Lab Exam 21 June Friday 2-5pm`
- **Type**: `assignment`  |  **Course**: `Computer Networks`  |  **Due Date**: `2026-06-26 09:00 UTC`
- **Confidence**: 1.0  |  **Needs Review**: False  |  **Latency**: 938.3ms

### [FAIL] #14: `PDC quiz tomorrow morning 9am chapter 5`
- **Type**: `quiz`  |  **Course**: `Parallel & Distributed Computing`  |  **Due Date**: `2026-06-23 04:00 UTC`
- **Confidence**: 1.0  |  **Needs Review**: False  |  **Latency**: 922.5ms

### [PASS] #15: `dbms quiz on ER diagrams next monday`
- **Type**: `quiz`  |  **Course**: `Advanced DBMS`  |  **Due Date**: `2026-06-29 18:59 UTC`
- **Confidence**: 1.0  |  **Needs Review**: False  |  **Latency**: 1017.8ms

### [PASS] #16: `quiz of automata will be on Monday`
- **Type**: `quiz`  |  **Course**: `Theory of Automata`  |  **Due Date**: `2026-06-29 18:59 UTC`
- **Confidence**: 0.9  |  **Needs Review**: False  |  **Latency**: 898.0ms

### [PASS] #17: `entrepreneurship quiz hai kal slides 10 se 20 tak`
- **Type**: `quiz`  |  **Course**: `Technology Entrepreneurship`  |  **Due Date**: `2026-06-23 18:59 UTC`
- **Confidence**: 1.0  |  **Needs Review**: False  |  **Latency**: 580.9ms

### [PASS] #18: `AI driven software development quiz next class on transformers`
- **Type**: `quiz`  |  **Course**: `AI-Driven Software Development`  |  **Due Date**: `(none)`
- **Confidence**: 0.55  |  **Needs Review**: True  |  **Latency**: 1916.7ms

### [PASS] #19: `Assignment 3 Deadline: tomorrow 12PM`
- **Type**: `assignment`  |  **Course**: `(none)`  |  **Due Date**: `2026-06-23 07:00 UTC`
- **Confidence**: 0.85  |  **Needs Review**: False  |  **Latency**: 312.6ms

### [PASS] #20: `Submit assignment before 2PM on 25 June 2026`
- **Type**: `assignment`  |  **Course**: `(none)`  |  **Due Date**: `2026-06-25 09:00 UTC`
- **Confidence**: 0.85  |  **Needs Review**: False  |  **Latency**: 1107.7ms

### [PASS] #21: `tmr ADBMS test hai chapter 2 se`
- **Type**: `quiz`  |  **Course**: `Advanced DBMS`  |  **Due Date**: `2026-06-23 18:59 UTC`
- **Confidence**: 1.0  |  **Needs Review**: False  |  **Latency**: 720.3ms

### [PASS] #22: `quiz kal hai parha lo`
- **Type**: `quiz`  |  **Course**: `(none)`  |  **Due Date**: `2026-06-23 18:59 UTC`
- **Confidence**: 0.8  |  **Needs Review**: False  |  **Latency**: 856.9ms

### [FAIL] #23: `CN lab viva on friday`
- **Type**: `assignment`  |  **Course**: `Computer Networks`  |  **Due Date**: `2026-06-26 18:59 UTC`
- **Confidence**: 1.0  |  **Needs Review**: False  |  **Latency**: 547.0ms

### [PASS] #24: `AISD project milestone 2 due 30 june`
- **Type**: `assignment`  |  **Course**: `AI-Driven Software Development`  |  **Due Date**: `2026-06-30 18:59 UTC`
- **Confidence**: 1.0  |  **Needs Review**: False  |  **Latency**: 639.5ms
