import sys
import re
import dataclasses

import idaapi
import idc

def debugp(*args, **kwargs):
    print('[gdb_auto_memory]', *args, **kwargs)

class GDB(object):

    def sendRaw(self, cmd):
        #debugp('Sending GDB: %s' % cmd)
        return idc.send_dbg_command('`' + cmd)
    
    def getPid(self):
        ret = self.sendRaw('?')
        m = re.findall('thread:([0-9a-f]+);', ret)
        if not m:
            debugp('invalid ret for "?" from GDB: %s' % repr(ret))
        pid = int(m[0], 16)
        return pid

    def _raw_qXfer(self, cmd): 
        r = self.sendRaw(cmd)
        if r[0] == 'l':
            return False, r[1:]
        elif r[0] == 'm':
            return True, r[1:]
        else:
            raise Exception('Invalid qXfer ret: %s' % r)
    
    def qXfer(self, cmd_part, chunk_size=0x10):
        cur = 0
        ret = ''
        while True:
            has_more, data = self._raw_qXfer('%s%x,%x' % (cmd_part, cur, chunk_size))
            #debugp(repr(data))
            cur += chunk_size
            ret += data
            if not has_more:
                break
        return ret
    
    def raw_qXfer(self, cmd): 
        r = self.sendGdbRaw(cmd)
        if r[0] == 'l':
            return False, r[1:]
        elif r[0] == 'm':
            return True, r[1:]
        else:
            raise Exception('invalid qXfer ret: %s' % r)
    
    def _raw_vFile(self, cmd):
        r = self.sendRaw(cmd)
        if r[0] != 'F':
            raise Exception('invalid vFile ret: %s' % r)
        body = r[1:]
        m = re.match('^([0-9a-f\-]+)(?:,([0-9a-f\-]+)|)(?:;([\S\s]*?)|)$', body)
        if not m:
            raise Exception('invalid vFile ret: %s' % r)
        _result, _errno, _attachment = m.groups()
        result = int(_result, 16)
        errno = int(_errno, 16) if _errno is not None else None
        attachment = _attachment
        return result, errno, attachment

    def vFileOpen(self, path, flag, mode):
        result, _, _ = self._raw_vFile("vFile:setfs:0")
        assert result == 0
        fd, errno, _ = self._raw_vFile("vFile:open:%s,%x,%x" % (path.encode().hex(), flag, mode))
        if fd < 0:
            raise Exception('cannot file %s: server returned %d errno %d' % (path, fd, errno))
        return fd
    
    def vFileRead(self, fd, count, offset):
        readCount, errno, data = self._raw_vFile("vFile:pread:%x,%x,%x" % (fd, count, offset))
        return readCount, errno, data

    def vFileReadAll(self, path, chunk_size=0x10):
        fd = self.vFileOpen(path, 0, 0o666)
        off = 0
        ret = ''
        while True:
            readCount, errno, data = self.vFileRead(fd, chunk_size, off)
            if readCount < 0:
                raise Exception('error during vFile read, errno %d' % errno)
            off += readCount
            ret += data
            if readCount < chunk_size:
                break
        return ret

#threads = qXfer('qXfer:threads:read::')

def pidmaps(mapsData):
    MAPS_LINE_RE = re.compile(r"""
        ^(?P<addr_start>[0-9a-f]+)-(?P<addr_end>[0-9a-f]+)\s+  # Address
        (?P<perms>\S+)\s+                                     # Permissions
        (?P<offset>[0-9a-f]+)\s+                              # Map offset
        (?P<dev>\S+)\s+                                       # Device node
        (?P<inode>\d+)                                        # Inode
        (?:\s+(?P<pathname>.*)|)$                               # Pathname
    """, re.VERBOSE)
    ret = {}
    for l in mapsData.splitlines():
        m = MAPS_LINE_RE.match(l)
        if not m:
            debugp('Skipping maps line: %s' % l)
            continue
        addr_start, addr_end, perms, offset, dev, inode, pathname = m.groups()
        ret[int(addr_start, 16)] = {
            'start': int(addr_start, 16),
            'end': int(addr_end, 16),
            'mode': perms,
            'offset': int(offset, 16),
            'dev': dev,
            'inode': inode,
            'name': pathname,
        }
    return ret

@dataclasses.dataclass(frozen=True)
class Region:
    start: int
    end: int
    name: str
    mode: str # rwxp

def buildRegionInfo(r):
    return Region(name=r['name'], start=r['start'], end=r['end'], mode=r['mode'])

def getMemInfo(mapsData):
    maps = pidmaps(mapsData)
    debugp('Got maps:', maps)
    modMaps = {}
    for _, m in maps.items():
        name = m['name']
        if name not in modMaps:
            modMaps[name] = []
        modMaps[name].append(m)
    
    for modName, regions in modMaps.items():
        rr = regions[0]
        rrinfo = buildRegionInfo(rr)
        if rr['inode'] and rr['inode'] != '0':
            # is module
            startEA = min(r['start'] for r in regions)
            endEA = max(r['end'] for r in regions)
            yield ('mod', dataclasses.replace(rrinfo, start=startEA, end=endEA))
        else:
            for r in regions:
                yield ('other', buildRegionInfo(r))

class GDBMemoryWatcher():
    def __init__(self):
        self._lastData = set()
        self.g = GDB()
        # debugp('Current pid:', self.pid)
    
    @property
    def pid(self):
        return self.g.getPid()
    
    @property
    def lastData(self):
        d = getattr(sys.modules['__main__'], 'GDBMemory_lastData', None)
        if not d:
            return set()
        if d[0] != self.pid:
            debugp('pid changed from %d to %d, ignoring cache' % (d[0], self.pid))
            return set()
        return d[1]
    @lastData.setter
    def lastData(self, data):
        setattr(sys.modules['__main__'], 'GDBMemory_lastData', (self.pid, data))

    def update(self):
        mapsData = self.g.vFileReadAll('/proc/%d/maps' % self.g.getPid())
        debugp('Got raw map data:', mapsData)
        newData = set(repr(c) for c in getMemInfo(mapsData))
        #debugp(newData)

        # TODO: handle region unload
        diff = [eval(c) for c in newData - self.lastData]
        debugp('Last: ', self.lastData)
        debugp('New: ', newData)
        debugp('Diff: ', diff)
        self.lastData = newData

        def addDbgMod(name, base, size):
            ev = idaapi.debug_event_t()
            modinfo = ev.set_modinfo(idaapi.LIB_LOADED)
            modinfo.name = name
            modinfo.base = base
            modinfo.size = size
            modinfo.rebase_to = idaapi.BADADDR
            input_file_path = idaapi.dbg_get_input_path()
            if modinfo.name == input_file_path:
                modinfo.rebase_to = modinfo.base
            idaapi.handle_debug_event(ev, idaapi.RQ_SILENT|idaapi.RQ_SUSPEND)
        
        def addMemRegion(name, start, end, mode):
            m = idaapi.memory_info_t()
            m.start_ea = start
            m.end_ea = end
            m.sclass = 'DATA'
            m.name = name
            m.bitness = 2 # ///< Number of bits in segment addresses (0-16bit, 1-32bit, 2-64bit)
            m.perm = (idaapi.SEGPERM_READ if 'r' in mode else 0) | (idaapi.SEGPERM_WRITE if 'w' in mode else 0) | (idaapi.SEGPERM_EXEC if 'x' in mode else 0)
            return m
        
        # mm = idaapi.meminfo_vec_t()
        # # base memory
        # mm.push_back(addMemRegion('MEMORY', 0, idaapi.BADADDR - 1, 'rwxp'))
        # for typ, rr in diff:
        #     if typ == 'mod':
        #         addDbgMod(rr.name, rr.start, rr.end - rr.start)
        #         debugp('Adding module %s' % rr.name)
        #     else:
        #         mm.push_back(addMemRegion(rr.name, rr.start, rr.end, rr.mode))
        # idaapi.set_manual_regions(mm)
        for typ, rr in diff:
            if typ == 'mod':
                addDbgMod(rr.name, rr.start, rr.end - rr.start)
                debugp('Adding module %s' % rr.name)
            else:
                idaapi.add_segm(0, rr.start, rr.end, rr.name, 'UNK', idaapi.ADDSEG_NOAA)
        

class DbgHooks(idaapi.DBG_Hooks):
    def __init__(self, callback):
        super(DbgHooks, self).__init__()
        self.callback = callback

    def hook(self, *args):
        super(DbgHooks, self).hook(*args)

    def unhook(self, *args):
        super(DbgHooks, self).unhook(*args)

    def notify(self):
        self.callback()

    def dbg_suspend_process(self, *args):
        if len(args) > 0:
            event : idaapi.debug_event_t = args[0]
            allowed_flags = idaapi.PROCESS_STARTED \
                | idaapi.BREAKPOINT \
                | idaapi.EXCEPTION \
                | idaapi.LIB_LOADED \
                | idaapi.LIB_UNLOADED \
                | idaapi.PROCESS_ATTACHED
            # we ignored STEP event
            if event.eid() & allowed_flags:
                self.notify()

    def dbg_process_attach(self, pid, tid, ea, name, base, size):
        self.notify()

PLUGIN_NAME = 'gdb_auto_memory'
class gdb_auto_memory_plugin_t(idaapi.plugin_t):
    flags = 0
    comment = ""
    help = PLUGIN_NAME
    wanted_name = PLUGIN_NAME
    wanted_hotkey = "Ctrl-Alt-G"

    g_watcher = None
    g_curHook = None
    g_hooked = False
    
    def init(self):
        debugp("loading plugin...")
        self.g_watcher = GDBMemoryWatcher()
        self.g_curHook = DbgHooks(self.g_watcher.update)
        return idaapi.PLUGIN_KEEP

    def run(self, arg=0):
        # if not self.g_hooked:
        #     debugp("enabling debugger hook")
        #     self.g_curHook.hook()
        #     self.g_hooked = True
        # else:
        #     debugp("disabling debugger hook")
        #     self.g_curHook.hook()
        #     self.g_hooked = False
        debugp("refreshing memory")
        self.g_watcher.update()

    def term(self):
        self.g_curHook.unhook()

def PLUGIN_ENTRY():
    return gdb_auto_memory_plugin_t()

if __name__ == '__main__':
    w = GDBMemoryWatcher()
    w.update()