// Ghidra headless post-script: write a reviewer-readable function inventory.
// Runs inside analyzeHeadless on the imported native library.
// Output: $GHIDRA_INVENTORY_OUT (default ghidra-functions.tsv)
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;

import java.io.File;
import java.io.PrintWriter;

public class FunctionInventory extends GhidraScript {

    private static final int MAX_ROWS = 20000;

    @Override
    public void run() throws Exception {
        String out = System.getenv("GHIDRA_INVENTORY_OUT");
        File target = new File(out == null || out.isEmpty() ? "ghidra-functions.tsv" : out);

        long total = currentProgram.getFunctionManager().getFunctionCount();
        PrintWriter w = new PrintWriter(target, "UTF-8");
        try {
            w.println("# program\t" + currentProgram.getName()
                    + "\tlanguage\t" + currentProgram.getLanguageID()
                    + "\tfunctions\t" + total);
            w.println("# entry\tname\tsize\tflags");
            int written = 0;
            for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
                if (written >= MAX_ROWS) {
                    w.println("# truncated at " + MAX_ROWS + " rows of " + total);
                    break;
                }
                if (monitor.isCancelled()) {
                    w.println("# analysis cancelled by user");
                    break;
                }
                StringBuilder flags = new StringBuilder();
                if (f.isThunk()) {
                    flags.append("thunk,");
                }
                if (f.isExternal()) {
                    flags.append("external,");
                }
                w.println(f.getEntryPoint() + "\t" + f.getName() + "\t"
                        + f.getBody().getNumAddresses() + "\t" + flags);
                written++;
            }
        } finally {
            w.close();
        }
        println("FunctionInventory wrote " + written + " of " + total + " functions to " + target.getAbsolutePath());
    }
}
