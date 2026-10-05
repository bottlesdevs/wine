import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

CANDIDATE = Path(os.environ['EAGLE_CANDIDATE'])
ROOT = Path(os.environ['EAGLE_WAIT_TEST_ROOT'])
sys.path.insert(0, str(CANDIDATE / 'lib/eagle'))
from waits import WaitGraph


class WaitProvider(unittest.TestCase):
    def test_bounded_cycles_last_error_and_observer_controls(self):
        for attempt in range(3):
            for profile in ('crash', 'wait'):
                bundle = ROOT / f'{profile}-{attempt}'
                result = subprocess.run([str(CANDIDATE / 'bin/eagle'), 'run', '--wine', str(CANDIDATE / 'bin/wine'), '--prefix', str(ROOT / 'prefix'), '--session', str(bundle), '--profile', profile, '--timeout', '30', str(ROOT / 'target.exe')], capture_output=True, text=True, timeout=50)
                self.assertEqual(result.returncode, 0, result.stderr[-4000:])
                events = [json.loads(line) for line in (bundle / 'events.jsonl').read_text().splitlines()]
                self.assertEqual(next(item['code'] for item in events if item['kind'] == 'process_exit'), 0)
                providers = [item for item in events if item['kind'] == 'provider']
                if profile == 'crash':
                    self.assertFalse(providers)
                    continue
                self.assertTrue(providers)
                self.assertTrue(all(item['data']['provider'] == 8 for item in providers))
                graphs = [item['wait_graph'] for item in providers]
                cycles = [graph for graph in graphs if graph['cycles']]
                self.assertTrue(cycles, 'timed circular mutex waits were not observed')
                self.assertTrue(all(graph['coverage'] == 'partial' and not graph['lost_observations'] for graph in graphs))
                self.assertEqual(graphs[-1]['cycles'], [])
                self.assertEqual(graphs[-1]['edges'], [])
                self.assertTrue(any(item['data']['event'] == 'WaitEnd' and item['data']['value'] == 258 for item in providers))
                self.assertTrue(all('not proof of a permanent deadlock' in graph['verdict'] for graph in cycles))

    def test_recursion_handle_reuse_and_budget_invalidate_graph(self):
        graph = WaitGraph()
        seq = 0
        def event(name, handle='a', tid=1, value=0, timeout=100):
            nonlocal seq
            seq += 1
            return graph.observe({'pid': 10, 'tid': tid, 'seq': seq, 'kind': 'provider', 'data': {'provider': 8, 'event': name, 'object': handle, 'value': value, 'timeout_ms': timeout}})
        event('MutexCreate', value=1)
        event('WaitBegin')
        self.assertEqual(event('WaitEnd', value=0)['edges'], [])
        event('MutexRelease', value=1)
        self.assertEqual(event('WaitBegin', tid=2)['edges'][0]['owner_tid'], 1)
        event('MutexRelease', value=1)
        self.assertEqual(event('WaitBegin', tid=2)['edges'], [])
        event('HandleClose', value=1)
        event('MutexCreate', tid=2, value=1)
        self.assertEqual(event('WaitBegin', tid=1)['edges'][0]['owner_tid'], 2)
        invalidated = event('ObserverBudgetExceeded')
        self.assertTrue(invalidated['lost_observations'])
        self.assertEqual(invalidated['edges'], [])
        self.assertEqual(event('WaitBegin', tid=1)['cycles'], [])


if __name__ == '__main__':
    unittest.main(verbosity=2)
