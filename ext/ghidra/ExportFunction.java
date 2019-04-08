import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.app.util.headless.HeadlessScript;

/*
 * Print out found functions' address. Do not consider external functions.
 * This script can be run as a preScript, Ghidra already have functions at this point.
 */
public class ExportFunction extends HeadlessScript {

	@Override
	public void run() throws Exception {
		// Find and print found functions
		Listing listing = currentProgram.getListing();
		FunctionIterator iter = listing.getFunctions(true);
		while (iter.hasNext() && !monitor.isCancelled()) {
			Function f = iter.next();
			if (f.isExternal()) {
				continue;
			}
			/*
			 * Let's consider already labeled functions
			String fName = f.getName();
			if (!fName.startsWith("FUN_")) {
				continue;
			}
			*/
			Address entry = f.getEntryPoint();
			if (entry != null) {
				println(String.format("0x%x", entry.getOffset()));
			}
		}
		setHeadlessContinuationOption(HeadlessContinuationOption.ABORT_AND_DELETE);

	}
}
