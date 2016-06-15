"Module for function address guessing"
import logging

from miasm2.core.asmbloc import asm_block_bad, log_asmbloc

from sibyl.heuristics.heuristic import Heuristic

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


class FuncHeuristic(Heuristic):
    """Provide heuristic for function start address detection"""

    # Enabled passes
    heuristics = [recursive_call]

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
