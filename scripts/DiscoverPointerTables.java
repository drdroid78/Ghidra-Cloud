// Conservative discovery of consecutive aligned pointers into executable memory.
// Candidate discovery, not proof of runtime dispatch or a definite call graph edge.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import java.io.*;
import java.nio.file.*;
import java.util.*;
public class DiscoverPointerTables extends GhidraScript {
    record Candidate(Address slot, Address target) {}
    int recovered=0, tables=0, failed=0, skipped=0;
    private void flush(List<Candidate> run, PrintWriter out) throws Exception {
        if (run.size()<3 || run.stream().map(Candidate::target).distinct().count()<3) {run.clear();return;}
        tables++;
        for(Candidate c:run) {
            monitor.checkCancelled();
            Function f=getFunctionAt(c.target());
            String status="existing";
            if(f==null) {
                if(getFunctionContaining(c.target())!=null || recovered>=4096) {status="skipped";skipped++;}
                else {
                    if(getInstructionAt(c.target())==null) disassemble(c.target());
                    f=getFunctionAt(c.target());
                    if(f==null && getInstructionAt(c.target())!=null && getFunctionContaining(c.target())==null)
                        f=createFunction(c.target(),null);
                    if(f!=null){status="recovered";recovered++;}
                    else{status="failed";failed++;}
                }
            }
            out.println(tables+"\t"+c.slot()+"\t"+c.target()+"\t"+status);
        }
        run.clear();
    }
    @Override public void run() throws Exception {
        String[] args=getScriptArgs();
        if(args.length!=1) throw new IllegalArgumentException("report path");
        Memory mem=currentProgram.getMemory();
        int width=currentProgram.getDefaultPointerSize();
        long scanned=0;
        boolean capped=false;
        AddressSpace space=currentProgram.getAddressFactory().getDefaultAddressSpace();
        try(PrintWriter out=new PrintWriter(Files.newBufferedWriter(Paths.get(args[0])))){
            out.println("table\tslot\ttarget\tstatus");
            if(width==4 || width==8) {
                for(MemoryBlock block:mem.getBlocks()){
                    if(!block.isLoaded() || !block.isInitialized() || block.isExecute() || !block.getStart().getAddressSpace().equals(space)) continue;
                    List<Candidate> run=new ArrayList<>();
                    long start=Long.remainderUnsigned(block.getStart().getOffset(),width);
                    for(long pos=(width-start)%width;pos<=block.getSize()-width;pos+=width){
                        if((scanned+=width)>16L*1024*1024){capped=true;break;}
                        monitor.checkCancelled();
                        Address slot=block.getStart().add(pos);
                        long val=width==8?mem.getLong(slot):Integer.toUnsignedLong(mem.getInt(slot));
                        Address target=null;
                        try {target=space.getAddress(val);}catch(Exception ignored){}
                        MemoryBlock dest=target==null?null:mem.getBlock(target);
                        boolean valid=dest!=null && dest.isLoaded() && dest.isInitialized() && dest.isExecute()
                            && (getFunctionContaining(target)==null || getFunctionAt(target)!=null)
                            && (getInstructionContaining(target)==null || getInstructionAt(target)!=null)
                            && getDataContaining(target)==null;
                        // Undefined data can be reported by Ghidra as a Data object; reject only defined data.
                        if(!valid && dest!=null && dest.isLoaded() && dest.isInitialized() && dest.isExecute()
                            && (getFunctionContaining(target)==null || getFunctionAt(target)!=null)
                            && (getInstructionContaining(target)==null || getInstructionAt(target)!=null)
                            && getDefinedDataContaining(target)==null) valid=true;
                        if(valid){run.add(new Candidate(slot,target)); if(run.size()>=4096)flush(run,out);}
                        else flush(run,out);
                    }
                    flush(run,out);
                    if(capped)break;
                }
                analyzeChanges(currentProgram);
            }
            if(out.checkError()) throw new IOException("pointer table report write failed");
        }
        println("POINTER_TABLES_OK scanned="+scanned+" tables="+tables+" recovered="+recovered+" failed="+failed+" skipped="+skipped+" capped="+capped);
    }
}
