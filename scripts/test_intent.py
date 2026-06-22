import sys
sys.path.insert(0, '.')
from utils.agent import classify_intent

cases = [
    ('hi',                       'greeting'),
    ('hello',                    'greeting'),
    ('salam',                    'greeting'),
    ('ok',                       'greeting'),
    ('thanks',                   'greeting'),
    ('who teaches pdc',          'query_schedule'),
    ('who teaches automata',     'query_schedule'),
    ('when is cn lab',           'query_schedule'),
    ('next class kab hai',       'query_schedule'),
    ('where is pdc class today', 'query_schedule'),
    ('what assignments do i have','query_tasks'),
    ('show my pending tasks',    'query_tasks'),
    ('PDC assignment due friday','save_task'),
    ('kal TOA ka quiz hai',      'save_task'),
    ('cn project 30 june tak',   'save_task'),
]

passed = 0
for msg, expected in cases:
    got = classify_intent(msg)
    ok = got == expected
    label = 'PASS' if ok else 'FAIL'
    print(f'  {label} | expected={expected:15s} got={got:15s} | {msg}')
    if ok:
        passed += 1

print(f'\n{passed}/{len(cases)} passed')
