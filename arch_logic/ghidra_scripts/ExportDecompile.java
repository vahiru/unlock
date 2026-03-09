// ExportDecompile.java - Ghidra Headless Script
// 功能：根据地址或函数名导出反编译 C 伪代码或反汇编列表
// 当 native decompiler 不可用时(如 ARM64 Linux)，自动降级为导出反汇编

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.util.task.TaskMonitor;

public class ExportDecompile extends ghidra.app.script.GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length == 0) {
            println("Usage: ExportDecompile <address_hex>");
            return;
        }

        String target = args[0];
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        Function func = null;

        // 先尝试通过名字查找
        for (Function f : funcMgr.getFunctions(true)) {
            if (f.getName().equalsIgnoreCase(target)) {
                func = f;
                break;
            }
        }

        // 如果名字找不到，尝试按地址查找
        if (func == null) {
            try {
                Address addr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(target);
                func = funcMgr.getFunctionContaining(addr);
                if (func == null) {
                    // 如果该地址没有函数，尝试在该地址创建函数
                    func = funcMgr.getFunctionAt(addr);
                }
            } catch (Exception e) {
                println("Could not parse address: " + target);
            }
        }

        // 如果以上都失败了，尝试导出该地址附近的反汇编
        if (func == null) {
            println("Function not found for: " + target + ", exporting raw disassembly around address...");
            try {
                Address addr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(target);
                exportDisassembly(addr, 100);
            } catch (Exception e) {
                println("Failed to export disassembly: " + e.getMessage());
            }
            return;
        }

        // 尝试反编译 (需要 native decompiler)
        boolean decompiled = false;
        try {
            DecompInterface decomp = new DecompInterface();
            decomp.openProgram(currentProgram);
            DecompileResults res = decomp.decompileFunction(func, 60, TaskMonitor.DUMMY);
            if (res != null && res.decompileCompleted() && res.getDecompiledFunction() != null) {
                String cCode = res.getDecompiledFunction().getC();
                if (cCode != null && !cCode.isEmpty()) {
                    println("---DECOMP_START---");
                    println(cCode);
                    println("---DECOMP_END---");
                    decompiled = true;
                }
            }
        } catch (Exception e) {
            println("Decompiler unavailable: " + e.getMessage());
        }

        // 降级：如果反编译不可用，导出反汇编列表
        if (!decompiled) {
            println("Decompiler not available, falling back to disassembly listing...");
            println("---DECOMP_START---");
            println("// Disassembly listing for: " + func.getName() + " @ " + func.getEntryPoint());
            println("// (Native decompiler unavailable on this platform)");
            exportDisassembly(func.getEntryPoint(), 200);
            println("---DECOMP_END---");
        }
    }

    private void exportDisassembly(Address startAddr, int maxInstructions) {
        Listing listing = currentProgram.getListing();
        InstructionIterator iter = listing.getInstructions(startAddr, true);
        int count = 0;
        while (iter.hasNext() && count < maxInstructions) {
            Instruction insn = iter.next();
            println(String.format("  0x%s:  %s  %s",
                insn.getAddress().toString(),
                insn.getMnemonicString(),
                insn.getDefaultOperandRepresentation(0)
                    + (insn.getNumOperands() > 1 ? ", " + insn.getDefaultOperandRepresentation(1) : "")
                    + (insn.getNumOperands() > 2 ? ", " + insn.getDefaultOperandRepresentation(2) : "")
            ));
            count++;
        }
        if (count == 0) {
            println("  (No instructions found at " + startAddr + ")");
        }
    }
}
