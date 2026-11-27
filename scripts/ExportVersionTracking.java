import ghidra.app.script.GhidraScript;
import ghidra.feature.vt.api.main.*;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.Function;
import java.io.*;
import java.nio.file.*;
public class ExportVersionTracking extends GhidraScript {
    String esc(Object o){return String.valueOf(o).replace("\t"," ").replace("\r"," ").replace("\n"," ");}
    @Override public void run() throws Exception{
        String[] a=getScriptArgs();
        if(a.length!=2)throw new IllegalArgumentException("session name and output directory");
        DomainFile df=state.getProject().getProjectData().getRootFolder().getFile(a[0]);
        if(df==null)throw new IllegalStateException("VT session missing");
        // Version Tracking synchronizes the destination program, so close the script transaction first.
        end(true);
        VTSession s=(VTSession)df.getDomainObject(this,true,false,monitor);
        int count=0, functionCount=0, accepted=0;
        try(PrintWriter out=new PrintWriter(Files.newBufferedWriter(Paths.get(a[1],"version-tracking.tsv")))){
            out.println("match_set\tcorrelator\ttype\tstatus\tsource\tsource_name\tdestination\tdestination_name\tsimilarity\tconfidence\tsource_length\tdestination_length");
            for(VTMatchSet ms:s.getMatchSets()){
                for(VTMatch m:ms.getMatches()){
                    monitor.checkCancelled();
                    VTAssociation as=m.getAssociation();
                    Function src=m.getSourceAddress()==null?null:s.getSourceProgram().getFunctionManager().getFunctionAt(m.getSourceAddress());
                    Function dst=m.getDestinationAddress()==null?null:s.getDestinationProgram().getFunctionManager().getFunctionAt(m.getDestinationAddress());
                    out.println(ms.getID()+"\t"+esc(ms.getProgramCorrelatorInfo())+"\t"+as.getType()+"\t"+as.getStatus()+"\t"+m.getSourceAddress()+"\t"+esc(src==null?"":src.getName())+"\t"+m.getDestinationAddress()+"\t"+esc(dst==null?"":dst.getName())+"\t"+m.getSimilarityScore()+"\t"+m.getConfidenceScore()+"\t"+m.getSourceLength()+"\t"+m.getDestinationLength());
                    count++; if(src!=null&&dst!=null)functionCount++;if(as.getStatus().toString().equals("ACCEPTED"))accepted++;
                }
            }
            if(out.checkError())throw new IOException("VT report write failed");
        }finally{s.release(this);}
        Files.writeString(Paths.get(a[1],"version-tracking-summary.txt"),"MATCH_ROWS="+count+"\nFUNCTION_MATCH_ROWS="+functionCount+"\nACCEPTED_ROWS="+accepted+"\n");
        println("VERSION_TRACKING_OK matches="+count+" functions="+functionCount+" accepted="+accepted);
    }
}
