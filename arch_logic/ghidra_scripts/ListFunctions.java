// ListFunctions.java - Ghidra Headless Script
// 功能：列出二进制中识别到的所有函数，并输出名称和地址
// 用于在 raw binary 中自动定位关键函数

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolIterator;

public class ListFunctions extends ghidra.app.script.GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        // 可选参数：过滤关键字（逗号分隔）
        String filterKeywords = args.length > 0 ? args[0] : "";
        String[] keywords = filterKeywords.isEmpty() ? new String[0] : filterKeywords.split(",");

        FunctionManager funcMgr = currentProgram.getFunctionManager();
        int count = 0;

        println("---FUNC_LIST_START---");
        for (Function func : funcMgr.getFunctions(true)) {
            String name = func.getName();
            String addr = func.getEntryPoint().toString();

            // 如果有过滤关键字，只输出匹配的
            if (keywords.length > 0) {
                boolean matched = false;
                for (String kw : keywords) {
                    if (name.toLowerCase().contains(kw.toLowerCase().trim())) {
                        matched = true;
                        break;
                    }
                }
                if (!matched) continue;
            }

            println(addr + " " + name);
            count++;
        }
        println("---FUNC_LIST_END---");
        println("Total functions listed: " + count);
    }
}
