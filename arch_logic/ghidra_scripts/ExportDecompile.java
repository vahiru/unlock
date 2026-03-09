import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

public class ExportDecompile extends ghidra.app.script.GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length == 0) {
            println("Usage: ExportDecompile <function_name_or_address>");
            return;
        }
        
        String target = args[0];
        Function func = null;
        
        // 此处简化了根据名字或地址寻找 Function 的逻辑
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            if (f.getName().equals(target) || f.getEntryPoint().toString().equals(target)) {
                func = f;
                break;
            }
        }
        
        if (func == null) {
            println("Function not found: " + target);
            return;
        }
        
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        DecompileResults res = decomp.decompileFunction(func, 30, TaskMonitor.DUMMY);
        
        if (res.decompileCompleted()) {
            println("---DECOMP_START---");
            println(res.getDecompiledFunction().getC());
            println("---DECOMP_END---");
        } else {
            println("Decompilation failed");
        }
    }
}
