"Module for function address guessing"
import logging
import re

from miasm2.core.asmbloc import asm_block_bad, log_asmbloc

from sibyl.heuristics.heuristic import Heuristic
import sibyl.heuristics.csts as csts


def recursive_call(func_heur, addresses=None):
    """Try to find new functions by following subroutines calls"""
    # Prepare disassembly engine
    dis_engine = func_heur.machine.dis_engine
    cont = func_heur.cont
    mdis = dis_engine(cont.bin_stream, symbol_pool=cont.symbol_pool)
    if addresses is None:
        addresses = [cont.entry_point]
    mdis.follow_call = True

    # Launch disassembly
    cur_log_level = log_asmbloc.level
    log_asmbloc.setLevel(logging.CRITICAL)

    label2block = {}

    for start_addr in addresses:
        cfg_temp = mdis.dis_multibloc(start_addr)

        # Merge label2block, take care of disassembly order due to cache
        for node in cfg_temp.nodes():
            label2block.setdefault(node.label, node)
    log_asmbloc.setLevel(cur_log_level)

    # Find potential addresses
    addresses = {}
    for bbl in label2block.itervalues():
        if len(bbl.lines) == 0:
            continue
        last_line = bbl.lines[-1]
        if last_line.is_subcall():
            for constraint in bbl.bto:
                if constraint.c_t != "c_to" or \
                   constraint.label not in label2block:
                    continue

                succ = label2block[constraint.label]
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
        ret = regexp.finditer(data[offset:])
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

    def do_votes(self):
        """Call recursive_call at the end"""
        do_recursive = False
        if recursive_call in self.heuristics:
            do_recursive = True
            self.heuristics.remove(recursive_call)

        super(FuncHeuristic, self).do_votes()
        addresses = self._votes

        if do_recursive:
            new_addresses = recursive_call(self,
                                           [addr
                                            for addr, vote in addresses.iteritems()
                                            if vote > 0])
            for addr, vote in new_addresses.iteritems():
                addresses[addr] = addresses.get(addr, 0) + vote
        self._votes = addresses

    def guess(self):
        for address, value in self.votes.iteritems():
            # Heuristic may vote negatively
            if value > 0:
                yield address
