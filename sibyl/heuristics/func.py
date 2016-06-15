"Module for function address guessing"
import logging
import re

from miasm2.core.asmbloc import asm_block_bad, log_asmbloc

from sibyl.heuristics.heuristic import Heuristic
import sibyl.heuristics.csts as csts


def recursive_call(func_heur, start_addr=None):

    # Prepare disassembly engine
    dis_engine = func_heur.machine.dis_engine
    cont = func_heur.cont
    mdis = dis_engine(cont.bin_stream, symbol_pool=cont.symbol_pool)
    if start_addr is None:
        start_addr = cont.entry_point
    mdis.follow_call = True

    # Launch disassembly
    cur_log_level = log_asmbloc.level
    log_asmbloc.setLevel(logging.CRITICAL)
    cfg = mdis.dis_multibloc(start_addr)
    log_asmbloc.setLevel(cur_log_level)

    # Find potential addresses
    addresses = {}
    for bbl in cfg.nodes():
        if len(bbl.lines) == 0:
            continue
        last_line = bbl.lines[-1]
        if last_line.is_subcall():
            for succ in cfg.successors(bbl):
                if cfg.edges2constraint[(bbl, succ)] != "c_to":
                    continue

                # Avoid redirectors
                if len(succ.lines) == 0 or succ.lines[0].dstflow():
                    continue

                # Avoid unmapped block and others relative bugs
                if isinstance(succ, asm_block_bad):
                    continue

                addresses[succ.label.offset] = 1

    return addresses


def _virt_find(virt, pattern):
    """Search @pattern in elfesteem @virt instance
    Inspired from elf_init.virt.find
    """
    regexp = re.compile(pattern)
    offset = 0
    sections = []
    for s in virt.parent.ph:
        s_max = s.ph.memsz
        if offset < s.ph.vaddr + s_max:
            sections.append(s)

    if not sections:
        raise StopIteration
    offset -= sections[0].ph.vaddr
    if offset < 0:
        offset = 0
    for s in sections:
        data = virt.parent.content[s.ph.offset:s.ph.offset + s.ph.filesz]
        ret = regexp.finditer(pattern, data[offset:])
        yield ret, s.ph.vaddr
        offset = 0


def pattern_matching(func_heur):
    """Search for function by pattern matching"""

    # Retrieve info
    architecture = func_heur.machine.name
    prologs = csts.func_prologs.get(architecture, [])
    data = func_heur.cont.bin_stream.bin

    addresses = {}

    # Search for function prologs

    pattern = "(" + ")|(".join(prologs) + ")"
    for find_iter, vaddr_base in _virt_find(data, pattern):
        for match in find_iter:
            addr = match.start() + vaddr_base
            addresses[addr] = 1

    return addresses


class FuncHeuristic(Heuristic):
    """Provide heuristic for function start address detection"""

    # Enabled passes
    heuristics = [
        pattern_matching,
        recursive_call,
    ]

    def __init__(self, cont, machine):
        """
        @cont: miasm2's Container instance
        @machine: miasm2's Machine instance
        """
        super(FuncHeuristic, self).__init__()
        self.cont = cont
        self.machine = machine

    def guess(self):
        for address, value in self.votes.iteritems():
            # Heuristic may vote negatively
            if value > 0:
                yield address
