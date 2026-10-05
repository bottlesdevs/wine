class WaitGraph:
    scope = 'observed KernelBase mutex handles within each process'

    def __init__(self):
        self.objects = {}
        self.waiting = {}
        self.incomplete = set()

    def observe(self, event):
        pid, tid = event['pid'], event['tid']
        if event['kind'] == 'process_exit':
            self.objects.pop(pid, None)
            self.waiting.pop(pid, None)
            self.incomplete.discard(pid)
            return None
        if event['kind'] == 'thread_exit':
            self.waiting.get(pid, {}).pop(tid, None)
            for obj in self.objects.get(pid, {}).values():
                if obj['owner_tid'] == tid:
                    obj.update(owner_tid=None, depth=0)
            return None
        if event['kind'] != 'provider' or event['data']['provider'] != 8:
            return None
        data = event['data']
        operation = data['event']
        objects = self.objects.setdefault(pid, {})
        waiting = self.waiting.setdefault(pid, {})
        handle = data.get('object')
        if operation == 'ObserverBudgetExceeded':
            self.incomplete.add(pid)
            objects.clear(); waiting.clear()
        elif pid not in self.incomplete:
            if operation == 'MutexCreate':
                if len(objects) >= 4096:
                    self.incomplete.add(pid)
                    objects.clear(); waiting.clear()
                else:
                    objects[handle] = {'id': event['seq'], 'owner_tid': tid if data['value'] else None, 'depth': int(bool(data['value']))}
            elif operation == 'HandleClose' and data['value']:
                objects.pop(handle, None)
                for thread, item in list(waiting.items()):
                    if item['handle'] == handle: waiting.pop(thread)
            elif operation == 'MutexRelease' and data['value'] and handle in objects:
                obj = objects[handle]
                if obj['owner_tid'] == tid:
                    obj['depth'] -= 1
                    if obj['depth'] == 0: obj['owner_tid'] = None
            elif operation == 'WaitBegin' and handle in objects and data['timeout_ms']:
                if len(waiting) >= 1024:
                    self.incomplete.add(pid)
                    objects.clear(); waiting.clear()
                else:
                    waiting[tid] = {'handle': handle}
            elif operation == 'WaitEnd':
                waiting.pop(tid, None)
                if handle in objects and data['value'] in (0, 128):
                    obj = objects[handle]
                    obj['depth'] = obj['depth'] + 1 if obj['owner_tid'] == tid and data['value'] == 0 else 1
                    obj['owner_tid'] = tid
        edges = []
        links = {}
        for thread, wait in waiting.items():
            obj = objects.get(wait['handle'])
            if obj and obj['owner_tid'] is not None and obj['owner_tid'] != thread:
                owner = obj['owner_tid']
                edges.append({'waiter_tid': thread, 'owner_tid': owner, 'handle': wait['handle'], 'object_id': obj['id']})
                links[thread] = owner
        cycles = set()
        for thread in links:
            path = []
            while thread in links and thread not in path:
                path.append(thread)
                thread = links[thread]
            if thread in path:
                cycle = path[path.index(thread):]
                pivot = cycle.index(min(cycle))
                cycles.add(tuple(cycle[pivot:] + cycle[:pivot]))
        return {'scope': self.scope, 'coverage': 'partial', 'lost_observations': pid in self.incomplete, 'edges': edges, 'cycles': [list(cycle) for cycle in sorted(cycles)], 'verdict': 'observed wait cycle; not proof of a permanent deadlock' if cycles else 'no cycle among observed waits'}
