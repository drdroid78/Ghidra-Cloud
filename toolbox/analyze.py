#!/usr/bin/env python3
"""Format-based offline analysis with public-only inputs and explicit evidence."""
import os, sys, re, json, csv, struct, hashlib, gzip, io, zipfile, shutil, signal, subprocess, resource
from pathlib import Path
import lief
import capstone as cs

ROOT=Path(os.environ["GITHUB_WORKSPACE"]).resolve()
BASE=Path(os.environ["RUNNER_TEMP"])/"toolbox"
REPORT=BASE/"report"
MAX_INPUT=100*1024*1024
MAX_UNPACK=128*1024*1024
TOOLS=("jadx","apktool","binwalk","radare2","yara","capstone","tshark","lief","ghidra")

def save(p,obj):
    p.write_text(json.dumps(obj,indent=2,ensure_ascii=False,default=str)+"\n")

def sha(p):
    with p.open("rb") as f: return hashlib.file_digest(f,"sha256").hexdigest()

def repo_file(s):
    p=(ROOT/s).resolve(strict=True)
    if not p.is_relative_to(ROOT) or not p.is_file() or not 0<p.stat().st_size<=MAX_INPUT:
        raise ValueError("Expected nonempty public repository file <=100 MiB")
    return p

def limits():
    resource.setrlimit(resource.RLIMIT_FSIZE,(64*1024*1024,64*1024*1024))
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))

def run(args, log, seconds=120, stderr=None):
    args=[str(x) for x in args]
    with log.open("wb") as f:
        err=stderr.open("wb") if stderr else None
        try:
            with subprocess.Popen(args,stdout=f,stderr=err or subprocess.STDOUT,
                    cwd=BASE,start_new_session=True,preexec_fn=limits) as p:
                try: rc=p.wait(timeout=seconds)
                except subprocess.TimeoutExpired:
                    os.killpg(p.pid,signal.SIGKILL);p.wait()
                    raise RuntimeError(f"Timeout: {args[0]}")
            if rc!=0:
                detail=(stderr or log).read_bytes()[-2000:].decode(errors="replace")
                raise RuntimeError(f"{args[0]} exit={rc}: {detail}")
        finally:
            if err: err.close()

def fixture_cmd(*args):
    subprocess.run([str(x) for x in args],check=True,timeout=120,cwd=BASE)

def zip_inventory(p):
    with zipfile.ZipFile(p) as z:
        rows=[]; total=0; seen=set()
        for item in z.infolist():
            name=item.filename
            if len(rows)>=20000 or name in seen or name.startswith(("/", "\\")) or "\\" in name or ".." in Path(name).parts or ":" in name or "\x00" in name:
                raise ValueError("Unsafe or oversized ZIP inventory")
            seen.add(name);total+=item.file_size
            if total>MAX_UNPACK or ((item.external_attr>>16)&0o170000)==0o120000 or item.flag_bits&1:
                raise ValueError("ZIP exceeds expanded size limit or contains symlink/encryption")
            rows.append({"name":name,"bytes":item.file_size,"compressed":item.compress_size})
        return rows

def identify(p):
    with p.open("rb") as f:h=f.read(16)
    if h[:4]==b"\x7fELF":return "elf"
    if h[:2]==b"MZ":return "pe"
    if h[:4].hex() in ("feedface","cefaedfe","feedfacf","cffaedfe","cafebabe","bebafeca","cafebabf","bfbafeca"):
        if h[:4]==b"\xca\xfe\xba\xbe" and p.suffix.lower()==".class":return "class"
        return "macho"
    if h[:4] in (b"\xd4\xc3\xb2\xa1",b"\xa1\xb2\xc3\xd4",b"\x4d\x3c\xb2\xa1",b"\xa1\xb2\x3c\x4d",b"\x0a\x0d\x0d\x0a"):return "pcap"
    if h.startswith(b"dex\n"):return "dex"
    if zipfile.is_zipfile(p):
        rows=zip_inventory(p);names={r["name"] for r in rows}
        if "AndroidManifest.xml" in names:return "apk"
        if any(n.endswith(".class") for n in names):return "jar"
        return "zip"
    return "raw"

def version_inventory():
    d=REPORT/"versions";d.mkdir(parents=True,exist_ok=True)
    for name,args in {"jadx":["jadx","--version"],"apktool":["apktool","--version"],"binwalk":["binwalk","--help"],"radare2":["radare2","-v"],"yara":["yara","--version"],"tshark":["tshark","--version"]}.items():
        run(args,d/(name+".txt"))
    save(d/"python.json",{"capstone":cs.__version__,"lief":lief.__version__})
    print("VERSIONS_OK",flush=True)

def native_structure(p,d):
    b=lief.parse(str(p))
    if b is None:raise ValueError("LIEF could not parse file")
    # Fat Mach-O: parse every slice instead of treating container as one ISA.
    binaries=list(b) if isinstance(b,lief.MachO.FatBinary) else [b]
    summary=[]
    for i,x in enumerate(binaries):
        sections=[]
        for s in x.sections:
            sections.append({"name":s.name,"virtual_address":s.virtual_address,"size":s.size,
                "offset":getattr(s,"offset",0),"flags":str(getattr(s,"flags",getattr(s,"characteristics","")))})
        summary.append({"slice":i,"type":type(x).__name__,"header":str(x.header),"entrypoint":x.entrypoint,
                        "sections":sections,"libraries":list(getattr(x,"libraries",[])),
                        "imported_functions":[str(v.name) for v in x.imported_functions][:20000]})
    save(d/"structure.json",summary)
    return binaries

def disasm(p,d,binaries,raw_arch="",raw_base=0):
    def engine(arch,bits,endian):
        e=cs.CS_MODE_BIG_ENDIAN if endian else cs.CS_MODE_LITTLE_ENDIAN
        if "X86" in arch or "I386" in arch or "AMD64" in arch: return cs.Cs(cs.CS_ARCH_X86,cs.CS_MODE_64 if bits==64 else cs.CS_MODE_32)
        if "AARCH64" in arch or "ARM64" in arch:return cs.Cs(cs.CS_ARCH_ARM64,e)
        if "THUMB" in arch:return cs.Cs(cs.CS_ARCH_ARM,cs.CS_MODE_THUMB|e)
        if "ARM" in arch:return cs.Cs(cs.CS_ARCH_ARM,cs.CS_MODE_ARM|e)
        if "MIPS" in arch:return cs.Cs(cs.CS_ARCH_MIPS,(cs.CS_MODE_MIPS64 if bits==64 else cs.CS_MODE_MIPS32)|e)
        if "RISCV" in arch:return cs.Cs(cs.CS_ARCH_RISCV,(cs.CS_MODE_RISCV64 if bits==64 else cs.CS_MODE_RISCV32)|cs.CS_MODE_RISCVC)
        if "PPC" in arch or "POWERPC" in arch:return cs.Cs(cs.CS_ARCH_PPC,(cs.CS_MODE_64 if bits==64 else cs.CS_MODE_32)|e)
        raise ValueError("Capstone unsupported architecture: "+arch)
    jobs=[]
    if binaries:
        for i,b in enumerate(binaries):
            h=b.header
            arch=str(getattr(h,"machine_type",getattr(h,"machine",getattr(h,"cpu_type","")))).upper()
            bits=64 if "64" in str(h) or "AMD64" in arch or "AARCH64" in arch else 32
            endian="MSB" in str(h) or "BIG" in str(h).upper()
            if isinstance(b,lief.ELF.Binary):bits=64 if "64" in str(h.identity_class) else 32;endian="MSB" in str(h.identity_data)
            for s in b.sections:
                if isinstance(b,lief.ELF.Binary):executable=bool(int(s.flags)&4)
                elif isinstance(b,lief.PE.Binary):executable=bool(int(s.characteristics)&0x20000000)
                else:executable=s.name=="__text"
                if executable and s.size:
                    va=s.virtual_address+(b.optional_header.imagebase if isinstance(b,lief.PE.Binary) else 0)
                    jobs.append((i,s.name,arch,bits,endian,va,bytes(s.content[:1024*1024])))
    elif raw_arch:
        arch=raw_arch.upper()
        jobs=[(0,"raw",arch,64 if "64" in arch else 32,arch.endswith("BE"),raw_base,p.read_bytes()[:1024*1024])]
    else:raise ValueError("RAW Capstone requires explicit architecture")
    count=0;errors=[]
    with (d/"instructions.tsv").open("w") as f:
        f.write("slice\tsection\taddress\tbytes\tmnemonic\toperands\n")
        for i,section,arch,bits,endian,addr,data in jobs:
            try:e=engine(arch,bits,endian)
            except Exception as exc:errors.append(str(exc));continue
            # Linear sweep is evidence, not a claim that all bytes are code.
            e.skipdata=True
            for ins in e.disasm(data,addr):
                if count>=50000:break
                f.write(f"{i}\t{section}\t0x{ins.address:x}\t{ins.bytes.hex()}\t{ins.mnemonic}\t{ins.op_str}\n");count+=1
            if count>=50000:break
    save(d/"summary.json",{"instructions":count,"errors":errors,"limit":50000,"per_section_bytes":1048576,"method":"linear sweep; skipdata rows are not instructions; ARM mode may require Thumb"})
    if not count:raise ValueError("No disassembly rows")

def binwalk_scan(p,d):
    run(["binwalk",p],d/"signatures.txt",180)
    # Only carve gzip identified by Binwalk. No external extractors or arbitrary archive paths.
    extracted=[];data=p.read_bytes()
    for line in (d/"signatures.txt").read_text(errors="replace").splitlines():
        m=re.search(r"(?i)(0x[0-9a-f]+)\s+.*gzip",line)
        if not m:continue
        off=int(m.group(1),16)
        if off<0 or off>=len(data) or data[off:off+3]!=b"\x1f\x8b\x08" or len(extracted)>=16:continue
        import zlib
        obj=zlib.decompressobj(31)
        remaining=MAX_UNPACK-sum(x["bytes"] for x in extracted)
        if remaining<=0:break
        try:
            decoded=obj.decompress(data[off:],remaining+1)
            if len(decoded)>remaining or not obj.eof:continue
        except zlib.error:continue
        target=d/f"gzip-{off:x}.bin";target.write_bytes(decoded)
        extracted.append({"offset":off,"bytes":len(decoded),"sha256":sha(target),"file":target.name})
    save(d/"extracted.json",extracted)

def apk_budget(p,d):
    rows=zip_inventory(p);save(d/"archive.json",rows)

def analyze(p,label,requested="auto",rules=None,raw_arch="",raw_base=0,raw_language="",raw_entry="",raw_compiler="default"):
    dest=REPORT/label;dest.mkdir(parents=True,exist_ok=True)
    fmt=identify(p)
    selected={"elf":["ghidra","radare2","lief","capstone","binwalk","yara"],"pe":["ghidra","radare2","lief","capstone","binwalk","yara"],"macho":["ghidra","radare2","lief","capstone","binwalk","yara"],"apk":["jadx","apktool","binwalk","yara"],"dex":["jadx","yara"],"jar":["jadx","yara"],"class":["jadx","yara"],"pcap":["tshark","yara"],"zip":["binwalk","yara"],"raw":["binwalk","yara"]}[fmt]
    if fmt=="raw" and raw_arch:selected.append("capstone")
    if fmt=="raw" and raw_language:selected.append("ghidra")
    if requested!="auto":
        selected=list(dict.fromkeys(x.strip() for x in requested.split(",") if x.strip()))
        if not selected or any(x not in TOOLS for x in selected):raise ValueError("Unknown analyzer")
    meta={"input":p.name,"size":p.stat().st_size,"sha256":sha(p),"format":fmt,"selected":selected,"tools":{}}
    save(dest/"manifest.json",meta)
    # Stage neutral filename: never interpret user-controlled filenames as flags.
    staged=BASE/"inputs"/label/("target."+fmt)
    staged.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(p,staged)
    binaries=None
    for tool in selected:
        d=dest/tool;d.mkdir(exist_ok=True)
        try:
            if tool=="lief":binaries=native_structure(staged,d)
            elif tool=="capstone":
                if fmt in ("elf","pe","macho") and binaries is None:binaries=native_structure(staged,d)
                disasm(staged,d,binaries,raw_arch,raw_base)
            elif tool=="radare2":
                run(["radare2","-N","-q","-e","scr.color=0","-c","ij",staged],d/"info.json",stderr=d/"info.log")
                run(["radare2","-N","-q","-e","scr.color=0","-c","aaa;aflj",staged],d/"functions.json",180,stderr=d/"functions.log")
                json.loads((d/"info.json").read_text());json.loads((d/"functions.json").read_text())
            elif tool=="binwalk":binwalk_scan(staged,d)
            elif tool=="yara":
                rule=rules or BASE/"default.yar"
                if rules and (rules.stat().st_size>1024*1024 or re.search(r"\binclude\b",rules.read_text())):raise ValueError("YARA includes not allowed")
                run(["yara","-a","30","-s","-m",rule,staged],d/"matches.txt",45)
            elif tool=="jadx":
                if fmt in ("apk","jar","zip"):apk_budget(staged,d)
                run(["jadx","--no-res","-j","2","-d",d/"decoded",staged],d/"log.txt",300)
            elif tool=="apktool":
                if fmt!="apk":raise ValueError("Apktool requires APK")
                apk_budget(staged,d)
                run(["apktool","d","-f","-o",d/"decoded",staged],d/"log.txt",300)
            elif tool=="tshark":
                if fmt!="pcap":raise ValueError("TShark requires pcap/pcapng")
                run(["tshark","-n","-r",staged,"-c","100000","-T","fields","-E","header=y","-e","frame.number","-e","frame.time_relative","-e","ip.src","-e","ip.dst","-e","ipv6.src","-e","ipv6.dst","-e","_ws.col.Protocol","-e","dns.qry.name","-e","tls.handshake.extensions_server_name"],d/"frames.tsv",180)
                run(["tshark","-n","-r",staged,"-c","100000","-q","-z","io,phs"],d/"protocols.txt",180)
            elif tool=="ghidra":
                # Reuse tested existing Ghidra implementation, no duplicate engine.
                sys.path.insert(0,str(ROOT/"scripts"))
                import cloud
                cloud.REPORT=REPORT/"ghidra-evidence"
                cloud.PROJECT=BASE/"ghidra-projects"
                cloud.REPORT.mkdir(exist_ok=True);cloud.PROJECT.mkdir(exist_ok=True)
                raw=(raw_language,hex(raw_base),raw_entry,raw_compiler) if fmt=="raw" and raw_language else None
                if fmt=="raw" and not raw:raise ValueError("Explicit Ghidra RAW language/base/entry required")
                result=cloud.analyze(staged,label,"*",os.getenv("QUERY",""),int(os.getenv("LIMIT","200")),raw)
                save(d/"evidence.json",{"report":str(result.relative_to(REPORT)),"summary":cloud.info(result)})
                if int(cloud.info(result)["DECOMPILED"])==0:raise ValueError("Ghidra did not decompile functions")
            meta["tools"][tool]={"status":"success","report":tool}
            print("TOOL_OK",label,tool,flush=True)
        except Exception as e:
            meta["tools"][tool]={"status":"failed","error":str(e)}
            print("TOOL_FAILED",label,tool,str(e),flush=True)
        save(dest/"manifest.json",meta)
    return meta

def make_fixtures():
    d=BASE/"fixtures";d.mkdir(exist_ok=True)
    (d/"probe.c").write_text('const char marker[]="CLOUD_TOOLBOX_MARKER"; __attribute__((noinline)) int cloud_probe(int x){return x*3+7;} int main(){return cloud_probe(marker[0]);}')
    fixture_cmd("gcc","-O0","-g","-fno-pie","-no-pie","-o",d/"probe.elf",d/"probe.c")
    payload=b"CLOUD_TOOLBOX_MARKER\n"+b"safe firmware fixture\n"*100
    (d/"firmware.bin").write_bytes(b"\x00"*4096+gzip.compress(payload,mtime=0))
    (d/"payload.expected").write_bytes(payload)
    # Real DNS request in Ethernet/IPv4/UDP encapsulation, generated offline.
    dns=struct.pack("!6H",1,0x0100,1,0,0,0)+b"\x07example\x04test\x00"+struct.pack("!HH",1,1)
    udp=struct.pack("!4H",12345,53,len(dns)+8,0)+dns
    ip=struct.pack("!BBHHHBBH4s4s",0x45,0,len(udp)+20,1,0,64,17,0,b"\xc0\x00\x02\x01",b"\xc0\x00\x02\x02")+udp
    frame=b"\x00"*12+b"\x08\x00"+ip
    (d/"capture.pcap").write_bytes(struct.pack("<IHHIIII",0xa1b2c3d4,2,4,0,0,65535,1)+struct.pack("<IIII",1,0,len(frame),len(frame))+frame)
    sdk=Path(os.environ.get("ANDROID_HOME",os.environ.get("ANDROID_SDK_ROOT","/usr/local/lib/android/sdk")))
    kits=sorted((sdk/"build-tools").glob("*/"),reverse=True)
    kit=next(x for x in kits if (x/"aapt").exists() and (x/"d8").exists())
    platform=next(x for x in sorted((sdk/"platforms").glob("android-*"),reverse=True) if (x/"android.jar").exists())
    (d/"AndroidManifest.xml").write_text('<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="org.cloud.fixture"><uses-sdk android:minSdkVersion="21"/><application android:label="@string/app_name"/></manifest>')
    res=d/"res"/"values";res.mkdir(parents=True,exist_ok=True)
    (res/"strings.xml").write_text('<resources><string name="app_name">CloudFixture</string></resources>')
    (d/"Probe.java").write_text('package org.cloud.fixture; public class Probe { public static String marker(){return "CLOUD_TOOLBOX_MARKER";} public static int calculate(int x){return x*3+7;} }')
    classes=d/"classes";classes.mkdir(exist_ok=True)
    fixture_cmd("javac","--release","8","-d",classes,d/"Probe.java")
    dex=d/"dex";dex.mkdir(exist_ok=True)
    fixture_cmd(kit/"d8","--min-api","21","--output",dex,classes/"org/cloud/fixture/Probe.class")
    apk=d/"fixture.apk"
    fixture_cmd(kit/"aapt","package","-f","-M",d/"AndroidManifest.xml","-S",d/"res","-I",platform/"android.jar","-F",apk)
    with zipfile.ZipFile(apk,"a") as z:z.write(dex/"classes.dex","classes.dex")
    return d

def selftest():
    d=make_fixtures()
    reports=[analyze(d/"probe.elf","elf"),analyze(d/"fixture.apk","apk"),analyze(d/"firmware.bin","firmware"),analyze(d/"capture.pcap","pcap")]
    statuses={k for r in reports for k,v in r["tools"].items() if v["status"]=="success"}
    failures=[(r["format"],k,v) for r in reports for k,v in r["tools"].items() if v["status"]!="success"]
    save(REPORT/"selftest.json",{"tools_success":sorted(statuses),"failures":failures})
    assert not failures,failures
    assert statuses==set(TOOLS),statuses
    assert any("cloud_probe" in str(x.get("name","")) for x in json.loads((REPORT/"elf/radare2/functions.json").read_text()))
    assert json.loads((REPORT/"elf/lief/structure.json").read_text())[0]["sections"]
    assert "ret" in (REPORT/"elf/capstone/instructions.tsv").read_text()
    assert "CLOUD_TOOLBOX_MARKER" in (REPORT/"elf/yara/matches.txt").read_text()
    assert any("CLOUD_TOOLBOX_MARKER" in x.read_text(errors="replace") for x in (REPORT/"apk/jadx/decoded").rglob("*.java"))
    assert "org.cloud.fixture" in (REPORT/"apk/apktool/decoded/AndroidManifest.xml").read_text()
    assert "CloudFixture" in (REPORT/"apk/apktool/decoded/res/values/strings.xml").read_text()
    assert (REPORT/"firmware/binwalk/gzip-1000.bin").read_bytes()==(d/"payload.expected").read_bytes()
    assert "example.test" in (REPORT/"pcap/tshark/frames.tsv").read_text()
    assert "cloud_probe" in (REPORT/"ghidra-evidence/elf/decompiled.txt").read_text()
    print("TOOLBOX_SELFTEST_PASSED nine analyzers + routing + extraction",flush=True)

def main():
    REPORT.mkdir(parents=True,exist_ok=True)
    (BASE/"default.yar").write_text('rule CloudMarker { strings: $m = "CLOUD_TOOLBOX_MARKER" condition: $m }\\nrule ELF_Header { condition: uint32(0) == 0x464c457f }\\nrule ZIP_Header { condition: uint32(0) == 0x04034b50 }\\n'.replace("\\n","\n"))
    version_inventory()
    if os.getenv("MODE","selftest")=="selftest":selftest()
    else:
        p=repo_file(os.environ["INPUT_PATH"])
        rules=repo_file(os.environ["RULES_PATH"]) if os.getenv("RULES_PATH") else None
        meta=analyze(p,"input",os.getenv("ANALYZERS","auto"),rules,os.getenv("RAW_ARCH",""),int(os.getenv("RAW_BASE","0") or "0",16),os.getenv("RAW_LANGUAGE",""),os.getenv("RAW_ENTRY",""),os.getenv("RAW_COMPILER","default"))
        if any(v["status"]!="success" for v in meta["tools"].values()):raise RuntimeError("One or more analyzers failed; see manifest.json")
    # Preserve reusable Ghidra projects separately. Evidence reports refer to relative paths.
    if (BASE/"ghidra-projects").exists():
        shutil.make_archive(str(BASE/"ghidra-projects"),"gztar",BASE,"ghidra-projects")

if __name__=="__main__":main()
