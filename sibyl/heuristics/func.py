"Module for function address guessing"
import logging
import re
import tempfile
import subprocess
import os

from miasm2.core.asmblock import AsmBlockBad, log_asmblock

from sibyl.heuristics.heuristic import Heuristic
import sibyl.heuristics.csts as csts
from sibyl.config import config


def recursive_call(func_heur, addresses):
    """Try to find new functions by following subroutines calls"""
    # Prepare disassembly engine
    dis_engine = func_heur.machine.dis_engine
    cont = func_heur.cont
    loc_db = cont.loc_db
    mdis = dis_engine(cont.bin_stream, loc_db=loc_db)
    mdis.follow_call = True
    # Launch disassembly
    cur_log_level = log_asmblock.level
    log_asmblock.setLevel(logging.CRITICAL)

    label2block = {}

    for start_addr in addresses:
        try:
            cfg_temp = mdis.dis_multiblock(start_addr)
        except TypeError as error:
            log_asmblock.critical("While disassembling: %s", error)
            continue

        # Merge label2block, take care of disassembly order due to cache
        for node in cfg_temp.nodes():
            label2block.setdefault(node, cfg_temp.loc_key_to_block(node))
            # Avoid re-disassembling
            mdis.dont_dis.append(loc_db.get_location_offset(node))
    log_asmblock.setLevel(cur_log_level)

    # Find potential addresses
    addresses = {}
    for bbl in label2block.itervalues():
        if len(bbl.lines) == 0:
            continue
        last_line = bbl.lines[-1]
        if last_line.is_subcall():
            for constraint in bbl.bto:
                if constraint.c_t != "c_to" or \
                   constraint.loc_key not in label2block:
                    continue

                succ = label2block[constraint.loc_key]
                # Avoid redirectors
                if len(succ.lines) == 0 or succ.lines[0].dstflow():
                    continue

                # Avoid unmapped block and others relative bugs
                if isinstance(succ, AsmBlockBad):
                    continue

                addresses[loc_db.get_location_offset(succ.loc_key)] = 1

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
    data = func_heur.cont.bin_stream.bin.virt

    addresses = {}

    # Search for function prologs

    pattern = "(" + ")|(".join(prologs) + ")"
    for find_iter, vaddr_base in _virt_find(data, pattern):
        for match in find_iter:
            addr = match.start() + vaddr_base
            addresses[addr] = 1

    return addresses


def named_symbols(func_heur):
    """Return the addresses of named symbols"""

    cont = func_heur.cont
    loc_db = cont.loc_db

    # Use the entry point
    addresses = [cont.entry_point]
    # Add address of symbol with a name (like 'main')
    addresses += [loc_db.get_location_offset(loc)
                  for loc in loc_db.loc_keys
                  if loc_db.get_location_names(loc) is not None]
    return {addr: 1 for addr in addresses}


def ida_funcs(func_heur):
    """Use IDA heuristics to find functions"""

    idaq64_path = config.idaq64_path
    if not idaq64_path:
        return {}

    # Prepare temporary files: script and output
    tmp_script = tempfile.NamedTemporaryFile(suffix=".py", delete=True)
    tmp_out = tempfile.NamedTemporaryFile(suffix=".addr", delete=True)

    tmp_script.write("""idaapi.autoWait()
open("%s", "w").write("\\n".join("0x%%x" %% x for x in Functions()))
Exit(0)
""" % tmp_out.name)
    tmp_script.flush()

    # Launch IDA
    env = os.environ.copy()
    env["TVHEADLESS"] = "true"
    run = subprocess.Popen([idaq64_path, "-A",
                            "-OIDAPython:%s" % tmp_script.name,
                            func_heur.filename],
                            env=env,
                           stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE,
    )
    run.communicate()

    # Get back addresses
    tmp_out.seek(0)
    addresses = {int(x, 16): 1 for x in tmp_out}

    # Clean-up
    tmp_script.close()
    tmp_out.close()

    return addresses


class FuncHeuristic(Heuristic):
    """Provide heuristic for function start address detection"""

    # Enabled passes
    heuristics = [
        named_symbols,
        pattern_matching,
        recursive_call,
        ida_funcs,
    ]

    def __init__(self, cont, machine, filename):
        """
        @cont: miasm2's Container instance
        @machine: miasm2's Machine instance
        @filename: target's filename
        """
        super(FuncHeuristic, self).__init__()
        self.cont = cont
        self.machine = machine
        self.filename = filename

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
