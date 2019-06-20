"""
YARA rules Scanner class definitions 

[mjdorma@gmail.com]
"""

from __future__ import print_function
import sys
import os
import traceback
from glob import glob
from threading import Thread
from threading import Lock as ThreadLock
from threading import Event as ThreadEvent
if sys.version_info[0] < 3: #major
    from Queue import Queue as ThreadQueue
    from Queue import Empty as ThreadEmpty
else:
    from queue import Queue as ThreadQueue
    from queue import Empty as ThreadEmpty
from multiprocessing import Process
from multiprocessing import Lock as ProcessLock
from multiprocessing import Value 
from multiprocessing import Event as ProcessEvent
from multiprocessing.queues import JoinableQueue as ProcessQueue
from multiprocessing.queues import Empty as ProcessEmpty

import time
import atexit

import yara


EXECUTE_THREAD = 0
EXECUTE_PROCESS = 1
DEFAULT_EXECUTE_POOL = 4
DEFAULT_EXECUTE_TYPE = EXECUTE_THREAD
DEFAULT_STREAM_CHUNK_SIZE = 2**20
DEFAULT_STREAM_READAHEAD_LIMIT = 2**32
DEFAULT_STREAM_CHUNK_OVERLAP = 1


class Counter(object):
    def __init__(self, Lock, init=0):
        self._value = Value('i', init)
        self.lock = Lock()

    def inc(self):
        with self.lock:
            self._value.value += 1

    @property
    def value(self):
        return self._value.value


class Scanner(object):
    enqueuer = None 

    def __init__(self, rules=None,
                       execute_type=DEFAULT_EXECUTE_TYPE, 
                       execute_pool=DEFAULT_EXECUTE_POOL,
                       stream_chunk_size=DEFAULT_STREAM_CHUNK_SIZE,
                       stream_chunk_overlap=DEFAULT_STREAM_CHUNK_OVERLAP,
                       stream_readahead_limit=DEFAULT_STREAM_READAHEAD_LIMIT,
                       stream_chunk_read_max=None,
                       **kwargs):
        """Scanner - base Scanner class

        rules - rules object we'll be using to match against 

        optional kwargs:
            execute_type - type of execution pool 
            execute_pool - number of Threads or Process to utilise for pooled
                           execution
            stream_chunk_size - size in bytes to read from a stream 
            stream_chunk_overlap - percentage read overlap per chunk 
            steram_readahead_limit - size in bytes limit for stream read ahead
            stream_chunk_read_max - max number of chunks to read from a stream
 
        Note: 
            Define an enqueuer function if the enqueue operation will take
            a long time.  This function is executed asynchronously 
        """
        if execute_type == EXECUTE_THREAD:
            self.Queue = ThreadQueue
            self.Event = ThreadEvent
            self.Empty = ThreadEmpty
            self.Lock = ThreadLock
            self.Execute = Thread
        else:
            self.Queue = ProcessQueue
            self.Event = ProcessEvent
            self.Empty = ProcessEmpty
            self.Lock = ProcessLock
            self.Execute = Process
        self._execute_type = execute_type
        
        if rules is None:
            raise ValueError("No rules object passed into __init__")
        self._rules = rules
        self._chunk_size = stream_chunk_size
        self._chunk_overlap = int((stream_chunk_size * \
                                  stream_chunk_overlap) / 100)
        self._stream_chunk_read_max = stream_chunk_read_max  
        self._max_sq_size = int((stream_readahead_limit / \
                             (stream_chunk_size + self._chunk_overlap)) + 1)
        self._jq = self.Queue()
        self._rq = self.Queue()
        self._empty = self.Event()
        self._pool = []
        self._scanned = Counter(self.Lock)
        self._matches = Counter(self.Lock)
        self._errors = Counter(self.Lock)
        self.quit = self.Event()
        atexit.register(self.quit.set)

        if self.enqueuer is not None:
            t = Thread(target=self._enqueuer)
            t.daemon = True
            t.start()

        for i in range(execute_pool):
            t = self.Execute(target=self._run)
            t.daemon = True
            self._pool.append(t)
    
        for p in self._pool:
            p.start()

    @property
    def scanned(self):
        return self._scanned.value

    @property
    def matches(self):
        return self._matches.value

    @property
    def errors(self):
        return self._errors.value
    
    @property
    def sq_size(self):
        """contains the current scan queue size"""
        if self._execute_type == EXECUTE_THREAD:
            return self._jq.unfinished_tasks
        else:
            return self._jq.qsize() 

    @property
    def rq_size(self):
        """contains the current result queue size"""
        if self._execute_type == EXECUTE_THREAD:
            return self._rq.unfinished_tasks
        else:
            return self._rq.qsize()

    def enqueue_path(self, tag, filepath, **match_kwargs):
        self._jq.put(("match_path", tag, (filepath,), match_kwargs))

    def enqueue_data(self, tag, data, **match_kwargs):
        self._jq.put(("match_data", tag, (data,), match_kwargs))

    def enqueue_proc(self, tag, pid, **match_kwargs):
        self._jq.put(("match_proc", tag, (pid,), match_kwargs))

    def enqueue_stream(self, stream, basetag='stream'):
        data = stream.read(self._chunk_size + self._chunk_overlap)
        read_bytes = self._chunk_size - self._chunk_overlap
        read_max = self._stream_chunk_read_max  
        chunk_id = 0
        chunk_start = 0
        while data and not self.quit.is_set():
            chunk_end = chunk_start + len(data)
            tag = "%s[%s:%s]" % (basetag, chunk_start, chunk_end)
            self.enqueue_data(tag, data)
            if read_max is not None:
                read_max =- 1
                if read_max <= 0:
                    break
            while self.sq_size > self._max_sq_size and \
                        not self.quit.is_set():
                time.sleep(0.1)
            if self._chunk_overlap > 0:
                overlap = data[-1 * self._chunk_overlap:]
                data = stream.read(self._chunk_size)
                if not data:
                    break
                data = overlap + data
            else:
                data = stream.read(self._chunk_size)
            chunk_id += 1
            chunk_start = (chunk_id * self._chunk_size) - self._chunk_overlap

    def enqueue_end(self):
        """queue the exit condition.  Threads will complete once 
        they have exhausted the queues up to queue end"""
        self._jq.put(None)

    def _enqueuer(self):
        try:
            self.enqueuer()
            self.enqueue_end()
        except:
            # abort current operations
            self.quit.set()
            self._rq.put(None)
            print("Error in enqueuer: %s" % traceback.format_exc(),
                    file=sys.stderr)

    def _run(self):
        try:
            while not self._empty.is_set() and not self.quit.is_set():
                try:
                    job = self._jq.get(timeout=0.1)
                except self.Empty:
                    continue
                if job is None:
                    self._empty.set()
                    self._rq.put(None)
                    self._jq.task_done()
                    break
                try:
                    self._scanned.inc()
                    f, t, a, k = job
                    f = getattr(self._rules, f)
                    r = f(*a, **k)
                    if r:
                        self._matches.inc()
                except Exception:
                    self._errors.inc()
                    r = traceback.format_exc()
                finally:
                    self._rq.put((t, r))
                    self._jq.task_done()
        except Exception:
            print(traceback.format_exc(), file=sys.__stderr__)
        
    def join(self, timeout=None):
        for t in self._pool:
            t.join(timeout=timeout)

    def is_alive(self):
        for t in self._pool:
            if t.is_alive():
                return True
        return False

    def dequeue(self, timeout=None):
        r = self._rq.get(timeout=timeout)
        self._rq.task_done()
        return r

    def __iter__(self):
        while True:
            r = self.dequeue()
            if r is None:
                # Wait until the workers are complete then purge the queue
                self.join()
                for i in range(self._rq.qsize()):
                    yield self.dequeue()
                break
            yield r
        

class PathScanner(Scanner):
    def __init__(self, args=[], recurse_dirs=False, 
                filesize_gt=None, filesize_lt=None,
                path_end_include=None, path_end_exclude=None, 
                path_contains_include=None, path_contains_exclude=None, 
                **scanner_kwargs):
        """Enqueue paths for scanning
        
        args - a list of glob'able paths to be scanned

        optional kwargs:
            recurse_dirs - walk down all directories
            filesize_gt - exclude files which are greater than 
            filesize_lt - exclude files which are less than
            path_end_include - include paths that end with 
            path_end_exclude - exclude paths that end with
            path_contains_include - include paths that contain
            path_contains_exclude - exclude paths that contain

        scanner_kwargs - see Scanner definition for options

        """
        self._paths = []
        for path in args:
            paths = glob(path)
            if not paths:
                raise ValueError("Error reading path '%s'" % path)
            self._paths.extend(paths)
        self._recurse_dirs = recurse_dirs
        self._filesize_gt=filesize_gt
        self._filesize_lt=filesize_lt
        self._path_end_include = path_end_include
        self._path_end_exclude = path_end_exclude
        self._path_contains_include = path_contains_include
        self._path_contains_exclude = path_contains_exclude
        Scanner.__init__(self, **scanner_kwargs)

    def enqueuer(self):
        for path in self.paths:
            self.enqueue_path(path, path)

    def exclude_path(self, path):
        def do_test(pathtest, tests):
            return bool([a for a in filter(lambda test:pathtest(test), tests)])
        if self._filesize_gt is not None:
            filesize = os.path.getsize(path)
            if filesize > self._filesize_gt:
                return True
        if self._filesize_lt is not None:
            filesize = os.path.getsize(path)
            if filesize < self._filesize_lt:
                return True
        if self._path_contains_exclude is not None:
            if do_test(path.__contains__, self._path_contains_exclude):
                return True
        if self._path_end_exclude is not None:
            if do_test(path.endswith, self._path_end_exclude):
                return True
        exclude_on_not_include = False
        if self._path_contains_include is not None:
            if do_test(path.__contains__, self._path_contains_include):
                return False
            else:
                exclude_on_not_include = True 
        if self._path_end_include is not None:
            if do_test(path.endswith, self._path_end_include):
                return False
            else:
                exclude_on_not_include = True
        return False or exclude_on_not_include

    @property
    def paths(self):
        if self._recurse_dirs == True:
            listdir = os.walk
        else:
            def listdir(d):
                ls = [(f, os.path.join(d, f)) for f in os.listdir(d)]
                filenames = [f for f, _ in \
                                filter(lambda o: not os.path.isdir(o[1]), ls) ]
                return [(d, [] , filenames)]
        for p in self._paths:
            if self.quit.is_set():
               return 
            if os.path.isdir(p):
                for dirpath, dirnames, filenames in listdir(p):
                    for filename in filenames:
                        if self.quit.is_set():
                            return
                        a = os.path.join(dirpath, filename)
                        if self.exclude_path(a):
                            continue
                        yield a
            else:
                if self.exclude_path(p):
                    continue
                yield p

        
class PidScanner(Scanner):
    def __init__(self, args=[], **scanner_kwargs):
        """Enqueue pids for scanning

        args - list of process ids to scan

        scanner_kwargs - see Scanner definition for options        
        """
        pids = []
        for pid in args:
            try:
                if type(pid) is not int:
                    pid = int(pid)
                pids.append(pid)
            except ValueError:
                raise ValueError("PID %s was not an int" % (pid))
        self._pids = pids
        Scanner.__init__(self, **scanner_kwargs)

    def enqueuer(self):
        for pid in self._pids:
            self.enqueue_proc("%s"%pid, pid)


class FileChunkScanner(PathScanner):
    """Enqueue chunks of data from paths"""
    def enqueuer(self):
        for path in self.paths:
            try:
                with open(path, 'rb') as f:
                    self.enqueue_stream(f, basetag=path)
            except Exception as exc:
                print("Failed to enqueue %s - %s" % (path,
                                traceback.format_exc()), 
                            file=sys.stderr)


class StdinScanner(Scanner):
    """Enqueue chunks of data from 'stream'"""
    def enqueuer(self):
        try:
            self.enqueue_stream(sys.stdin)
        except Exception as exc:
            print("Error reading stream - %s" % (exc), file=sys.stderr)


class SyncScanner(Scanner):
    def __init__(self, **scanner_kwargs):
        """Synchronised matching - Use the Scanner's scan pool to process 
        match jobs synchronously

        scanner_kwargs - see Scanner definition for options
        """
        self._scan_id = 0
        self._new_results = Event()
        self.enqueuer = self.dequeuer # dequeuing thread
        self.results = {}
        Scanner.__init__(self, **scanner_kwargs)

    def dequeuer(self):
        try:
            while not self.quit.is_set():
                self._new_results.clear()
                ret = self.dequeue()
                if ret is None:
                    break
                scan_id, res = ret
                self.results[scan_id] = res
                self._new_results.set()
        finally:
            self._new_results.set()

    def _sync_scan(self, enqueue_fnc, args, match_kwargs):
        results = {}
        scan_ids = []
        for arg in args:
            self._scan_id += 1
            scan_id = self._scan_id
            scan_ids.append(scan_id)
            results[scan_id] = None
            a = (scan_id, arg)
            enqueue_fnc(*a, **match_kwargs)

        while not self.quit.is_set():
            for scan_id in scan_ids:
                if scan_id in self.results:
                    results[scan_id] = self.results.pop(scan_id)
                    if len(results) == len(scan_ids):
                        return [results[i] for i in scan_ids]
            while not self._new_results.wait(timeout=1):
                pass

    def match_paths(self, path_list, **match_kwargs):
        return self._sync_scan(self.enqueue_path, path_list, match_kwargs)

    def match_procs(self, pid_list, **match_kwargs):
        return self._sync_scan(self.enqueue_proc, pid_list, match_kwargs)

    def match_data(self, data_list, **match_kwargs):
        return self._sync_scan(self.enqueue_data, data_list, match_kwargs)


