// Ghidra Headless: bounded, evidence-oriented reports. Never executes the target.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.Scalar;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

public class CloudReport extends GhidraScript {
    private String esc(Object x) {
        return String.valueOf(x).replace("\\","\\\\").replace("\t","\\t").replace("\r","\\r").replace("\n","\\n");
    }
    private void row(PrintWriter w, Object... fields) {
        StringJoiner j = new StringJoiner("\t");
        for (Object f : fields) j.add(esc(f));
        w.println(j);
    }
    private PrintWriter writer(Path dir, String name) throws IOException {
        return new PrintWriter(Files.newBufferedWriter(dir.resolve(name), StandardCharsets.UTF_8));
    }
    private String functionAt(Address a) {
        Function f = currentProgram.getFunctionManager().getFunctionContaining(a);
        return f == null ? "" : f.getEntryPoint()+":"+f.getName();
    }
    private boolean match(String q, Object... vals) {
        if (q.isEmpty()) return false;
        for (Object v : vals) if (String.valueOf(v).toLowerCase(Locale.ROOT).contains(q)) return true;
        return false;
    }
    @Override public void run() throws Exception {
        String[] a = getScriptArgs();
        if (a.length != 4) throw new IllegalArgumentException("report directory, function filter, query, max decompilations");
        Path dir = Paths.get(a[0]); Files.createDirectories(dir);
        String filter = a[1].toLowerCase(Locale.ROOT), query = a[2].toLowerCase(Locale.ROOT);
        int limit = Integer.parseInt(a[3]);
        if (limit < 1 || limit > 5000) throw new IllegalArgumentException("limit 1..5000");
        Listing listing = currentProgram.getListing();
        int functions = 0, eligible = 0, attempted = 0, completed = 0, failed = 0, codeMatches = 0;
        long instructions = 0, constants = 0, refs = 0, strings = 0, calls = 0, dataItems = 0;
        boolean functionsCapped = false, instructionsCapped = false, refsCapped = false, dataCapped = false, constantsCapped = false;
        DecompInterface di = new DecompInterface();
        try (PrintWriter meta = writer(dir,"summary.txt");
             PrintWriter funcs = writer(dir,"functions.tsv");
             PrintWriter code = writer(dir,"decompiled.txt");
             PrintWriter str = writer(dir,"strings.tsv");
             PrintWriter con = writer(dir,"constants.tsv");
             PrintWriter xr = writer(dir,"xrefs.tsv");
             PrintWriter cg = writer(dir,"calls.tsv");
             PrintWriter hits = writer(dir,"matches.tsv")) {
            meta.println("PROGRAM="+currentProgram.getName());
            meta.println("LANGUAGE="+currentProgram.getLanguageID());
            meta.println("IMAGE_BASE="+currentProgram.getImageBase());
            meta.println("FILTER="+filter); meta.println("QUERY="+query); meta.println("DECOMPILE_LIMIT="+limit);
            row(funcs,"entry","name","body_addresses","instruction_count","instruction_sha256","fingerprint_complete");
            row(str,"address","value");
            row(con,"instruction","function","operand","hex","unsigned_decimal");
            row(xr,"from","to","type","from_function","to_function");
            row(cg,"site","caller","target","callee","type");
            row(hits,"kind","address","value");
            if (!di.openProgram(currentProgram)) throw new IllegalStateException("Decompiler open failed");
            FunctionIterator fi = currentProgram.getFunctionManager().getFunctions(true);
            while (fi.hasNext() && !monitor.isCancelled()) {
                if (functions >= 100000) { functionsCapped = true; break; }
                Function f = fi.next(); functions++;
                String entry = f.getEntryPoint().toString(), name = f.getName();
                boolean eligibleFunction = filter.equals("*") || match(filter,entry,name);
                if (eligibleFunction) eligible++;
                if (match(query,entry,name)) row(hits,"function",entry,name);
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                long count = 0;
                boolean complete = true;
                InstructionIterator ii = listing.getInstructions(f.getBody(),true);
                while (ii.hasNext() && !monitor.isCancelled()) {
                    if (instructions >= 2000000) { instructionsCapped = true; complete = false; break; }
                    Instruction ins = ii.next(); instructions++; count++;
                    md.update(ins.getBytes());
                    if (ins.getFlowType().isCall()) {
                        Address[] flows = ins.getFlows();
                        if (flows.length == 0) { row(cg,ins.getAddress(),entry+":"+name,"","","indirect/unresolved"); calls++; }
                        for (Address dst : flows) { row(cg,ins.getAddress(),entry+":"+name,dst,functionAt(dst),ins.getFlowType()); calls++; }
                    }
                    for (int op=0; op<ins.getNumOperands(); op++) {
                        for (Object obj : ins.getOpObjects(op)) {
                            if (!(obj instanceof Scalar)) continue;
                            Scalar scalar=(Scalar)obj;
                            String hex="0x"+Long.toUnsignedString(scalar.getUnsignedValue(),16);
                            String dec=Long.toUnsignedString(scalar.getUnsignedValue());
                            if (constants >= 500000) { constantsCapped=true; continue; }
                            row(con,ins.getAddress(),entry+":"+name,op,hex,dec); constants++;
                            if (match(query,hex,dec)) row(hits,"constant",ins.getAddress(),hex+" "+dec+" "+name);
                        }
                    }
                }
                row(funcs,entry,name,f.getBody().getNumAddresses(),count,HexFormat.of().formatHex(md.digest()),complete && !monitor.isCancelled());
                if (!eligibleFunction || attempted >= limit) continue;
                attempted++;
                DecompileResults dr = di.decompileFunction(f,20,monitor);
                if (dr.decompileCompleted() && dr.getDecompiledFunction()!=null) {
                    completed++;
                    String c = dr.getDecompiledFunction().getC();
                    code.println("\nFUNCTION "+entry+" "+name); code.println(c);
                    if (match(query,c)) {
                        codeMatches++;
                        for (String line : c.split("\\R")) if (match(query,line)) row(hits,"code",entry,line.trim());
                    }
                } else { failed++; code.println("\nFAILED "+entry+" "+name+" "+dr.getErrorMessage()); }
            }
            DataIterator data = listing.getDefinedData(true);
            while (data.hasNext() && !monitor.isCancelled()) {
                if (dataItems++ >= 1000000) { dataCapped=true; break; }
                Data d=data.next();
                if (!d.hasStringValue()) continue;
                Object v=d.getValue();
                if (!(v instanceof String)) continue;
                row(str,d.getAddress(),v); strings++;
                if (match(query,v)) row(hits,"string",d.getAddress(),v);
            }
            ReferenceIterator ri=currentProgram.getReferenceManager().getReferenceIterator(currentProgram.getMinAddress());
            while (ri.hasNext() && !monitor.isCancelled()) {
                if (refs >= 500000) { refsCapped=true; break; }
                Reference r=ri.next();
                row(xr,r.getFromAddress(),r.getToAddress(),r.getReferenceType(),functionAt(r.getFromAddress()),functionAt(r.getToAddress())); refs++;
                if (match(query,r.getFromAddress(),r.getToAddress(),functionAt(r.getFromAddress()),functionAt(r.getToAddress()))) row(hits,"xref",r.getFromAddress(),r.getToAddress()+" "+r.getReferenceType());
            }
            meta.println("FUNCTIONS="+functions);
            meta.println("ELIGIBLE="+eligible);
            meta.println("ATTEMPTED="+attempted);
            meta.println("DECOMPILED="+completed);
            meta.println("FAILED="+failed);
            meta.println("CODE_MATCHES="+codeMatches);
            meta.println("INSTRUCTIONS="+instructions);
            meta.println("CONSTANTS="+constants);
            meta.println("STRINGS="+strings);
            meta.println("XREFS="+refs);
            meta.println("CALLS="+calls);
            meta.println("FUNCTION_SCAN_CAPPED="+functionsCapped);
            meta.println("INSTRUCTION_SCAN_CAPPED="+instructionsCapped);
            meta.println("CONSTANT_SCAN_CAPPED="+constantsCapped);
            meta.println("DATA_SCAN_CAPPED="+dataCapped);
            meta.println("XREF_SCAN_CAPPED="+refsCapped);
            meta.println("DECOMPILE_CAPPED="+(eligible>attempted));
            meta.println("CANCELLED="+monitor.isCancelled());
            for (PrintWriter w : List.of(meta,funcs,code,str,con,xr,cg,hits)) if (w.checkError()) throw new IOException("Report write failed");
        } finally { di.dispose(); }
        if (monitor.isCancelled()) throw new IllegalStateException("Analysis cancelled");
        println("CLOUD_REPORT_OK functions="+functions+" decompiled="+completed+" failed="+failed);
    }
}
