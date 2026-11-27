import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
public class SeedRaw extends GhidraScript {
    @Override public void run() throws Exception {
        String[] args=getScriptArgs();
        if(args.length!=1) throw new IllegalArgumentException("Raw entry required");
        Address entry=currentProgram.getAddressFactory().getAddress(args[0]);
        if(entry==null || !currentProgram.getMemory().contains(entry)) throw new IllegalArgumentException("Entry outside imported memory");
        if(currentProgram.getListing().getInstructionAt(entry)==null) disassemble(entry);
        if(currentProgram.getFunctionManager().getFunctionAt(entry)==null) createFunction(entry,"raw_entry");
        if(currentProgram.getFunctionManager().getFunctionAt(entry)==null) throw new IllegalStateException("Could not create raw entry");
        println("RAW_ENTRY_OK "+entry);
    }
}
