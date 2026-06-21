# DueMate Evaluation Harness Report

> Generated: 2026-06-21 19:47 UTC

## 📊 Summary

| Metric | Value |
|:---|:---|
| **Overall Pass Rate** | 20/24 (83%) |
| Task Type Accuracy | 22/24 (91%) |
| Course Extraction Accuracy | 22/24 (91%) |
| Due Date Extraction Accuracy | 24/24 (100%) |
| Avg Latency | 207 ms |
| Avg Confidence Score | 0.72 |
| Parse Methods | {"regex_fallback": 24} |

## 🧪 Test Case Results

| # | Pass | Message | Type ✓ | Course ✓ | Date ✓ | Confidence | Latency | Method |
|---|:---:|---|:---:|:---:|:---:|:---:|---:|---|
| 1 | ❌ | `PDC assignment submit karna hai friday tak` | ✅ | ⚠️ | ✅ | 0.75 | 1.5ms | regex_fallback |
| 2 | ✅ | `Advanced DBMS assignment 3 due on 12 July 2026` | ✅ | ✅ | ✅ | 0.75 | 1690.8ms | regex_fallback |
| 3 | ✅ | `guys cn ka project 30 June 2026 tak jama karwana hai please note karlo` | ✅ | ✅ | ✅ | 0.75 | 46.5ms | regex_fallback |
| 4 | ✅ | `AI driven SE project due on 25 June 2026 before 5PM` | ✅ | ✅ | ✅ | 0.75 | 50.9ms | regex_fallback |
| 5 | ✅ | `Submit Theory of Automata assignment before Monday midnight` | ✅ | ✅ | ✅ | 0.75 | 0.6ms | regex_fallback |
| 6 | ✅ | `Here is complete assignment 4, student need to submit on 22 June 2026 …` | ✅ | ✅ | ✅ | 0.75 | 60.5ms | regex_fallback |
| 7 | ✅ | `entrepreneurship lab report due next wednesday` | ✅ | ✅ | ✅ | 0.75 | 0.7ms | regex_fallback |
| 8 | ✅ | `adbms lab assignment submit karein 15 july tak` | ✅ | ✅ | ✅ | 0.75 | 33.9ms | regex_fallback |
| 9 | ✅ | `Computer Networks assignment #2 is due on July 5, 11:59PM` | ✅ | ✅ | ✅ | 0.75 | 47.3ms | regex_fallback |
| 10 | ✅ | `Problem Solving 3 homework due kal` | ✅ | ✅ | ✅ | 0.75 | 0.4ms | regex_fallback |
| 11 | ✅ | `kal TOA ka quiz hai chapter 3 aur 4 se` | ✅ | ✅ | ✅ | 0.75 | 0.9ms | regex_fallback |
| 12 | ✅ | `Sir said next week AI class quiz related to neural networks and backpr…` | ✅ | ✅ | ✅ | 0.5 | 1485.8ms | regex_fallback |
| 13 | ❌ | `Computer Networks Lab Exam 21 June Friday 2-5pm` | ❌ | ✅ | ✅ | 0.75 | 0.6ms | regex_fallback |
| 14 | ❌ | `PDC quiz tomorrow morning 9am chapter 5` | ✅ | ⚠️ | ✅ | 0.75 | 0.3ms | regex_fallback |
| 15 | ✅ | `dbms quiz on ER diagrams next monday` | ✅ | ✅ | ✅ | 0.75 | 0.3ms | regex_fallback |
| 16 | ✅ | `quiz of automata will be on Monday` | ✅ | ✅ | ✅ | 0.75 | 0.2ms | regex_fallback |
| 17 | ✅ | `entrepreneurship quiz hai kal slides 10 se 20 tak` | ✅ | ✅ | ✅ | 0.75 | 0.2ms | regex_fallback |
| 18 | ✅ | `AI driven software development quiz next class on transformers` | ✅ | ✅ | ✅ | 0.5 | 1455.6ms | regex_fallback |
| 19 | ✅ | `Assignment 3 Deadline: tomorrow 12PM` | ✅ | ✅ | ✅ | 0.75 | 0.2ms | regex_fallback |
| 20 | ✅ | `Submit assignment before 2PM on 25 June 2026` | ✅ | ✅ | ✅ | 0.65 | 57.1ms | regex_fallback |
| 21 | ❌ | `tmr ADBMS test hai chapter 2 se` | ❌ | ✅ | ✅ | 0.75 | 0.6ms | regex_fallback |
| 22 | ✅ | `quiz kal hai parha lo` | ✅ | ✅ | ✅ | 0.75 | 0.2ms | regex_fallback |
| 23 | ✅ | `CN lab viva on friday` | ✅ | ✅ | ✅ | 0.75 | 0.2ms | regex_fallback |
| 24 | ✅ | `AISD project milestone 2 due 30 june` | ✅ | ✅ | ✅ | 0.75 | 33.5ms | regex_fallback |

## 📋 Detailed Results

### [FAIL] #1: `PDC assignment submit karna hai friday tak`
- **Type**: `assignment`  |  **Course**: `Parallel & Distributed Computing`  |  **Due Date**: `2026-06-26 18:59 UTC`
- **Confidence**: 0.75  |  **Needs Review**: False  |  **Latency**: 1.5ms

### [PASS] #2: `Advanced DBMS assignment 3 due on 12 July 2026`
- **Type**: `assignment`  |  **Course**: `Advanced DBMS`  |  **Due Date**: `2026-07-12 18:59 UTC`
- **Confidence**: 0.75  |  **Needs Review**: False  |  **Latency**: 1690.8ms

### [PASS] #3: `guys cn ka project 30 June 2026 tak jama karwana hai please note karlo`
- **Type**: `assignment`  |  **Course**: `Computer Networks`  |  **Due Date**: `2026-06-30 18:59 UTC`
- **Confidence**: 0.75  |  **Needs Review**: False  |  **Latency**: 46.5ms

### [PASS] #4: `AI driven SE project due on 25 June 2026 before 5PM`
- **Type**: `assignment`  |  **Course**: `AI-Driven Software Development`  |  **Due Date**: `2026-06-25 12:00 UTC`
- **Confidence**: 0.75  |  **Needs Review**: False  |  **Latency**: 50.9ms

### [PASS] #5: `Submit Theory of Automata assignment before Monday midnight`
- **Type**: `assignment`  |  **Course**: `Theory of Automata`  |  **Due Date**: `2026-06-29 18:59 UTC`
- **Confidence**: 0.75  |  **Needs Review**: False  |  **Latency**: 0.6ms

### [PASS] #6: `Here is complete assignment 4, student need to submit on 22 June 2026 …`
- **Type**: `assignment`  |  **Course**: `(none)`  |  **Due Date**: `2026-06-22 09:00 UTC`
- **Confidence**: 0.75  |  **Needs Review**: False  |  **Latency**: 60.5ms

### [PASS] #7: `entrepreneurship lab report due next wednesday`
- **Type**: `assignment`  |  **Course**: `Technology Entrepreneurship`  |  **Due Date**: `2026-06-24 18:59 UTC`
- **Confidence**: 0.75  |  **Needs Review**: False  |  **Latency**: 0.7ms

### [PASS] #8: `adbms lab assignment submit karein 15 july tak`
- **Type**: `assignment`  |  **Course**: `Advanced DBMS`  |  **Due Date**: `2026-07-15 18:59 UTC`
- **Confidence**: 0.75  |  **Needs Review**: False  |  **Latency**: 33.9ms

### [PASS] #9: `Computer Networks assignment #2 is due on July 5, 11:59PM`
- **Type**: `assignment`  |  **Course**: `Computer Networks`  |  **Due Date**: `2026-07-05 18:59 UTC`
- **Confidence**: 0.75  |  **Needs Review**: False  |  **Latency**: 47.3ms

### [PASS] #10: `Problem Solving 3 homework due kal`
- **Type**: `assignment`  |  **Course**: `(none)`  |  **Due Date**: `2026-06-23 18:59 UTC`
- **Confidence**: 0.75  |  **Needs Review**: False  |  **Latency**: 0.4ms

### [PASS] #11: `kal TOA ka quiz hai chapter 3 aur 4 se`
- **Type**: `quiz`  |  **Course**: `Theory of Automata`  |  **Due Date**: `2026-06-23 18:59 UTC`
- **Confidence**: 0.75  |  **Needs Review**: False  |  **Latency**: 0.9ms

### [PASS] #12: `Sir said next week AI class quiz related to neural networks and backpr…`
- **Type**: `quiz`  |  **Course**: `AI-Driven Software Development`  |  **Due Date**: `(none)`
- **Confidence**: 0.5  |  **Needs Review**: True  |  **Latency**: 1485.8ms

### [FAIL] #13: `Computer Networks Lab Exam 21 June Friday 2-5pm`
- **Type**: `exam`  |  **Course**: `Computer Networks`  |  **Due Date**: `2026-06-26 09:00 UTC`
- **Confidence**: 0.75  |  **Needs Review**: False  |  **Latency**: 0.6ms

### [FAIL] #14: `PDC quiz tomorrow morning 9am chapter 5`
- **Type**: `quiz`  |  **Course**: `Parallel & Distributed Computing`  |  **Due Date**: `2026-06-23 04:00 UTC`
- **Confidence**: 0.75  |  **Needs Review**: False  |  **Latency**: 0.3ms

### [PASS] #15: `dbms quiz on ER diagrams next monday`
- **Type**: `quiz`  |  **Course**: `Advanced DBMS`  |  **Due Date**: `2026-06-29 18:59 UTC`
- **Confidence**: 0.75  |  **Needs Review**: False  |  **Latency**: 0.3ms

### [PASS] #16: `quiz of automata will be on Monday`
- **Type**: `quiz`  |  **Course**: `Theory of Automata`  |  **Due Date**: `2026-06-29 18:59 UTC`
- **Confidence**: 0.75  |  **Needs Review**: False  |  **Latency**: 0.2ms

### [PASS] #17: `entrepreneurship quiz hai kal slides 10 se 20 tak`
- **Type**: `quiz`  |  **Course**: `Technology Entrepreneurship`  |  **Due Date**: `2026-06-23 18:59 UTC`
- **Confidence**: 0.75  |  **Needs Review**: False  |  **Latency**: 0.2ms

### [PASS] #18: `AI driven software development quiz next class on transformers`
- **Type**: `quiz`  |  **Course**: `AI-Driven Software Development`  |  **Due Date**: `(none)`
- **Confidence**: 0.5  |  **Needs Review**: True  |  **Latency**: 1455.6ms

### [PASS] #19: `Assignment 3 Deadline: tomorrow 12PM`
- **Type**: `assignment`  |  **Course**: `(none)`  |  **Due Date**: `2026-06-23 07:00 UTC`
- **Confidence**: 0.75  |  **Needs Review**: False  |  **Latency**: 0.2ms

### [PASS] #20: `Submit assignment before 2PM on 25 June 2026`
- **Type**: `assignment`  |  **Course**: `(none)`  |  **Due Date**: `2026-06-25 09:00 UTC`
- **Confidence**: 0.65  |  **Needs Review**: False  |  **Latency**: 57.1ms

### [FAIL] #21: `tmr ADBMS test hai chapter 2 se`
- **Type**: `exam`  |  **Course**: `Advanced DBMS`  |  **Due Date**: `2026-06-23 18:59 UTC`
- **Confidence**: 0.75  |  **Needs Review**: False  |  **Latency**: 0.6ms

### [PASS] #22: `quiz kal hai parha lo`
- **Type**: `quiz`  |  **Course**: `(none)`  |  **Due Date**: `2026-06-23 18:59 UTC`
- **Confidence**: 0.75  |  **Needs Review**: False  |  **Latency**: 0.2ms

### [PASS] #23: `CN lab viva on friday`
- **Type**: `quiz`  |  **Course**: `Computer Networks`  |  **Due Date**: `2026-06-26 18:59 UTC`
- **Confidence**: 0.75  |  **Needs Review**: False  |  **Latency**: 0.2ms

### [PASS] #24: `AISD project milestone 2 due 30 june`
- **Type**: `assignment`  |  **Course**: `AI-Driven Software Development`  |  **Due Date**: `2026-06-30 18:59 UTC`
- **Confidence**: 0.75  |  **Needs Review**: False  |  **Latency**: 33.5ms
