#!/usr/bin/env python3
"""Public-only Ghidra runner. Bounded inputs, no target execution."""
import csv
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
from collections import Counter
from pathlib import Path

ROOT = Path(os.environ["GITHUB_WORKSPACE"]).resolve()
WORK = Path(os.environ["RUNNER_TEMP"]) / "ghidra-cloud"
HEADLESS = WORK / "ghidra_12.2_PUBLIC/support/analyzeHeadless"
SCRIPTS = ROOT / "scripts"
REPORT = WORK / "report"
PROJECT = WORK / "project"
LIMIT_BYTES = 100 * 1024 * 1024

def cmd(*args, **kwargs):
    return subprocess.run([str(x) for x in args], check=True, **kwargs)

def sha(path):
    with path.open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()

def input_path(value):
    p = (ROOT / value).resolve(strict=True)
    if not p.is_relative_to(ROOT) or not p.is_file() or not 0 < p.stat().st_size <= LIMIT_BYTES:
        raise ValueError("Use a nonempty public repository file, at most 100 MiB")
    return p

def info(directory):
    return dict(line.split("=", 1) for line in (directory / "summary.txt").read_text().splitlines() if "=" in line)

def read_tsv(p):
    with p.open(encoding="utf-8") as f:
        return list(csv.DictReader(f, delimiter="\t"))

def analyze(path, label, filt="*", query="", limit=200, raw=None, resume=False):
    out = REPORT / (label + "-resumed" if resume else label)
    out.mkdir(parents=True, exist_ok=True)
    project = PROJECT / label
    project.mkdir(parents=True, exist_ok=True)
    if not 1 <= limit <= 5000:
        raise ValueError("max_functions must be 1..5000")
    args = [HEADLESS, project, "CloudAnalysis", "-max-cpu", "4", "-analysisTimeoutPerFile", "1200",
            "-scriptPath", SCRIPTS, "-log", out / "analysis.log"]
    if resume:
        args += ["-process", path, "-noanalysis"]
    else:
        # Avoid ambiguous or option-like names in the Ghidra project.
        name = "target" + (path.suffix if re.fullmatch(r"\.[A-Za-z0-9]{1,12}", path.suffix) else ".bin")
        staged = WORK / "inputs" / label / name
        staged.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, staged)
        (out / "input.sha256").write_text(sha(staged) + "\n")
        with (out / "input-format.txt").open("w") as f:
            cmd("file", "-b", staged, stdout=f)
        for encoding, filename in [("s", "ascii-offsets.txt"), ("l", "utf16le-offsets.txt")]:
            # Cap exported raw strings; pipe output through a bounded reader.
            with (out / filename).open("wb") as f:
                with subprocess.Popen(["strings", "-a", "-t", "x", "-e", encoding, str(staged)], stdout=subprocess.PIPE) as proc:
                    lines = 0
                    for line in proc.stdout:
                        if lines >= 100000 or f.tell() + len(line) > 20 * 1024 * 1024:
                            f.write(b"\n[OUTPUT CAPPED]\n")
                            proc.terminate()
                            break
                        f.write(line)
                        lines += 1
                    rc = proc.wait()
                    if rc not in (0, -15, -13):
                        raise RuntimeError("strings failed")
        args += ["-import", staged]
        if raw:
            language, base, entry, compiler = raw
            for v in (base, entry):
                if not re.fullmatch(r"(?:0x)?[0-9a-fA-F]{1,16}", v):
                    raise ValueError("raw addresses must be hexadecimal")
            if not re.fullmatch(r"[A-Za-z0-9:_-]+", language) or not re.fullmatch(r"[A-Za-z0-9_-]+", compiler):
                raise ValueError("Invalid language/compiler ID")
            (out / "raw-import.json").write_text(json.dumps({"language":language,"load_address_hex":base,"entry_address_hex":entry,"compiler":compiler},indent=2))
            args += ["-loader", "BinaryLoader", "-loader-baseAddr", "0x"+base.removeprefix("0x"),
                     "-processor", language, "-cspec", compiler, "-preScript", "SeedRaw.java", entry.removeprefix("0x")]
        (project / "input.json").write_text(json.dumps({"name": name, "sha256": sha(staged)}))
    args += ["-postScript", "CloudReport.java", out, "f:"+filt, "q:"+query, str(limit)]
    # Ghidra can exit zero despite script errors, so require explicit output and success marker.
    with (out / "headless-console.log").open("w") as f:
        cmd(*args, stdout=f, stderr=subprocess.STDOUT)
    console = (out / "headless-console.log").read_text(errors="replace")
    if "CLOUD_REPORT_OK" not in console or (raw and "RAW_ENTRY_OK" not in console):
        print(console[-12000:], flush=True)
        raise RuntimeError("Ghidra script did not complete")
    if info(out).get("CANCELLED") != "false":
        raise RuntimeError("Report cancelled")
    if not (project / "CloudAnalysis.gpr").exists() or not (project / "CloudAnalysis.rep").is_dir():
        raise RuntimeError("Persistent Ghidra project not found")
    print(label, info(out), flush=True)
    return out

def compare(a, b, report_a, report_b):
    dest = REPORT / "comparison"
    dest.mkdir(exist_ok=True)
    aa, bb = a.read_bytes(), b.read_bytes()
    changed = 0
    ranges = 0
    start = None
    with (dest / "byte-ranges.tsv").open("w") as f:
        f.write("start_hex\tend_exclusive_hex\n")
        for i, (x,y) in enumerate(zip(aa, bb)):
            if x != y:
                changed += 1
                if start is None: start=i
            elif start is not None:
                ranges += 1
                if ranges <= 10000: f.write(f"{start:x}\t{i:x}\n")
                start=None
        common = min(len(aa),len(bb))
        if start is not None:
            ranges += 1
            if ranges <= 10000: f.write(f"{start:x}\t{common:x}\n")
        if len(aa)!=len(bb):
            ranges += 1
            if ranges <= 10000: f.write(f"{common:x}\t{max(len(aa),len(bb)):x}\n")
    left, right = read_tsv(report_a/"functions.tsv"), read_tsv(report_b/"functions.tsv")
    ca, cb = Counter(x["name"] for x in left), Counter(x["name"] for x in right)
    byname = {x["name"]:x for x in right if cb[x["name"]]==1}
    byaddr = {x["entry"]:x for x in right}
    ia, ib = info(report_a), info(report_b)
    compatible = ia["LANGUAGE"]==ib["LANGUAGE"] and ia["IMAGE_BASE"]==ib["IMAGE_BASE"]
    matched = set()
    counts = Counter()
    with (dest/"functions-diff.tsv").open("w",newline="") as f:
        w=csv.writer(f,delimiter="\t")
        w.writerow(["match_method","status","a_entry","a_name","b_entry","b_name","a_instruction_sha256","b_instruction_sha256"])
        for x in left:
            y=None; method="none"
            if ca[x["name"]]==1 and not re.match(r"^(FUN_|thunk_|LAB_|sub_)",x["name"],re.I):
                y=byname.get(x["name"])
                if y and ia["LANGUAGE"]==ib["LANGUAGE"]: method="unique_name"
                else: y=None
            if not y and compatible:
                candidate=byaddr.get(x["entry"])
                if candidate and (x["name"]==candidate["name"] or re.match(r"^(FUN_|thunk_|LAB_|sub_)",x["name"],re.I)):
                    y=candidate; method="address_heuristic"
            if y and y["entry"] in matched: y=None; method="none"
            if y:
                matched.add(y["entry"])
                state="incomplete" if x["fingerprint_complete"]!="true" or y["fingerprint_complete"]!="true" else ("same_instruction_bytes" if x["instruction_sha256"]==y["instruction_sha256"] else "changed_instruction_bytes")
                w.writerow([method,state,x["entry"],x["name"],y["entry"],y["name"],x["instruction_sha256"],y["instruction_sha256"]])
            else:
                state="unmatched_a"; w.writerow([method,state,x["entry"],x["name"],"","",x["instruction_sha256"],""])
            counts[state]+=1
        for y in right:
            if y["entry"] not in matched:
                counts["unmatched_b"]+=1
                w.writerow(["none","unmatched_b","","",y["entry"],y["name"],"",y["instruction_sha256"]])
    result={"sha256_a":sha(a),"sha256_b":sha(b),"size_a":len(aa),"size_b":len(bb),"different_overlapping_bytes":changed,
            "extra_or_missing_bytes":abs(len(aa)-len(bb)),"ranges":ranges,"ranges_capped":ranges>10000,
            "same_language_and_base":compatible,"function_results":dict(counts),
            "warning":"Byte offsets are aligned without insertion detection. Function matching is by unique name or address heuristic, not semantic equivalence. Relocations and optimization can change hashes. Unmatched is not proof of added/deleted code."}
    (dest/"summary.json").write_text(json.dumps(result,indent=2))
    print("COMPARISON",result,flush=True)

def package():
    target=WORK/"ghidra-project.tar.gz"
    with tarfile.open(target,"w:gz") as t:
        t.add(PROJECT,arcname="project")
    print("PROJECT_SAVED",target.stat().st_size,flush=True)

def restore(run_id):
    if not re.fullmatch(r"[1-9][0-9]{0,19}",run_id):
        raise ValueError("Invalid run ID")
    repo=os.environ["GITHUB_REPOSITORY"]
    meta=json.loads(subprocess.check_output(["gh","api",f"repos/{repo}/actions/runs/{run_id}"]))
    same_run = run_id == os.environ.get("GITHUB_RUN_ID") and os.getenv("MODE") == "resume_test" and meta.get("status") == "in_progress"
    if ((meta.get("conclusion")!="success" and not same_run) or meta.get("head_branch")!="main"
        or meta.get("path")!=".github/workflows/ghidra-cloud.yml" or meta.get("head_repository",{}).get("full_name")!=repo):
        raise ValueError("Restore only successful main-branch runs of this workflow")
    download=WORK/"restore"
    download.mkdir(exist_ok=True)
    cmd("gh","run","download",run_id,"--repo",repo,"--name","ghidra-project","--dir",download)
    with tarfile.open(download/"ghidra-project.tar.gz","r:gz") as t:
        members=t.getmembers()
        if sum(m.size for m in members)>8*1024**3 or len(members)>100000:
            raise ValueError("Oversized project")
        if any(not (m.isfile() or m.isdir()) or not Path(m.name).is_relative_to("project") or ".." in Path(m.name).parts for m in members):
            raise ValueError("Unsafe project archive")
        t.extractall(WORK,filter="data",members=members)
    print("PROJECT_RESTORED",run_id,flush=True)

def selftest():
    fixture=WORK/"fixture"
    fixture.mkdir(exist_ok=True)
    template='''#include <stdio.h>
const char cloud_marker[] = "CLOUD_MARKER_TEST_123";
__attribute__((noinline)) int cloud_probe(int x) { return x + MAGIC; }
__attribute__((noinline)) int cloud_caller(int x) { puts(cloud_marker); return cloud_probe(x); }
int main(void) { return cloud_caller(5); }
'''
    for name, magic in [("a", "0x12345678"),("b","0x12345679")]:
        src=fixture/f"{name}.c"; src.write_text(template.replace("MAGIC",magic))
        cmd("gcc","-O0","-g","-fno-pie","-no-pie","-o",fixture/f"{name}.elf",src)
    a,b=fixture/"a.elf",fixture/"b.elf"
    ra=analyze(a,"a","*","cloud_marker",200)
    rb=analyze(b,"b","*","cloud_probe",200)
    s=info(ra)
    assert int(s["DECOMPILED"])>0 and int(s["XREFS"])>0 and int(s["CALLS"])>0 and int(s["CONSTANTS"])>0
    assert "CLOUD_MARKER_TEST_123" in (ra/"strings.tsv").read_text()
    hits=read_tsv(ra/"matches.tsv")
    assert any(x["kind"]=="string" for x in hits) and any(x["kind"]=="code" for x in hits),hits
    assert any("cloud_probe" in x["callee"] and "cloud_caller" in x["caller"] for x in read_tsv(ra/"calls.tsv"))
    marker=next(x["address"] for x in read_tsv(ra/"strings.tsv") if "CLOUD_MARKER_TEST_123" in x["value"])
    assert any(x["to"]==marker for x in read_tsv(ra/"xrefs.tsv"))
    compare(a,b,ra,rb)
    diff=read_tsv(REPORT/"comparison/functions-diff.tsv")
    assert any(x["a_name"]=="cloud_probe" and x["status"]=="changed_instruction_bytes" for x in diff)
    assert any(x["a_name"]=="cloud_caller" and x["status"]=="same_instruction_bytes" for x in diff)
    raw=fixture/"raw.bin"; raw.write_bytes(bytes.fromhex("b878563412c3"))
    rr=analyze(raw,"raw","*","0x12345678",50,raw=("x86:LE:64:default","1000","1000","gcc"))
    assert any(int(x["entry"],16)==0x1000 and x["name"]=="raw_entry" for x in read_tsv(rr/"functions.tsv"))
    assert any(x["kind"]=="constant" for x in read_tsv(rr/"matches.tsv"))
    assert "raw_entry" in (rr/"decompiled.txt").read_text()
    src=fixture/"arm.c"
    src.write_text("volatile int x=5; __attribute__((noinline)) int probe(int v){return v*3+7;} int entry(void){return probe(x);}")
    for target,label,arch in [("armv7-none-eabi","arm32","ARM"),("aarch64-linux-gnu","arm64","AARCH64")]:
        elf=fixture/f"{label}.elf"
        cmd("clang",f"--target={target}","-fuse-ld=lld","-nostdlib","-static","-fno-stack-protector","-O1","-Wl,-e,entry","-Wl,--strip-all","-o",elf,src)
        r=analyze(elf,label,"*","",200)
        s=info(r)
        assert s["LANGUAGE"].upper().startswith(arch+":") and int(s["DECOMPILED"])>0,s
    # Larger stripped ELF: 256 noinline functions and a dispatch table.
    src=fixture/"large.c"
    funcs="\n".join(f"__attribute__((noinline)) int f{i}(int x){{return x+{i+1000};}}" for i in range(256))
    table=",".join(f"f{i}" for i in range(256))
    src.write_text(funcs+"\nint (*volatile table[256])(int)={"+table+"};\nint main(int argc,char**argv){return table[argc&255](argc);}")
    elf=fixture/"large.elf"
    cmd("gcc","-O2","-s","-fno-pie","-no-pie","-o",elf,src)
    indirect=analyze(elf,"indirect","*","",500)
    print("INDIRECT_FIXTURE_COVERAGE expected_functions_at_least=256 detected="+info(indirect)["FUNCTIONS"],flush=True)
    assert int(info(indirect)["DECOMPILED"])>0
    # Test large-scale enumeration separately, with direct references to every function.
    direct="\n".join(f"__attribute__((noinline)) int f{i}(int x){{return x+{i+1000};}}" for i in range(256))
    direct+="\nint main(int argc,char**argv){int x=argc;"+"".join(f"x=f{i}(x);" for i in range(256))+"return x;}"
    src.write_text(direct)
    cmd("gcc","-O2","-s","-fno-pie","-no-pie","-o",elf,src)
    lr=analyze(elf,"large","*","",500)
    assert int(info(lr)["FUNCTIONS"])>=256 and int(info(lr)["DECOMPILED"])>=250,info(lr)
    # Reopen an already saved project, search a known constant and compare the prior fingerprint.
    first=PROJECT/"a"/"input.json"
    name=json.loads(first.read_text())["name"]
    restored=analyze(name,"a","*","0x12345678",200,resume=True)
    assert any(x["kind"]=="constant" for x in read_tsv(restored/"matches.tsv"))
    print("SELF_TEST_PASSED: code, strings, scalars, xrefs, calls, comparison, raw, ARM32, ARM64, larger stripped ELF, reopen",flush=True)

def main():
    WORK.mkdir(exist_ok=True); REPORT.mkdir(exist_ok=True); PROJECT.mkdir(exist_ok=True)
    filt=os.getenv("FILTER","*") or "*"; query=os.getenv("QUERY","")
    limit=int(os.getenv("LIMIT","200"))
    if len(query)>512 or len(filt)>512 or "\n" in query or "\n" in filt:
        raise ValueError("Search parameters must be single line, at most 512 characters")
    mode=os.getenv("MODE","selftest") or "selftest"
    if mode=="selftest": selftest()
    elif mode in ("resume","resume_test"):
        restore(os.environ["RESUME_RUN"])
        label=os.getenv("RESUME_LABEL","a") or "a"
        if not re.fullmatch(r"[a-zA-Z0-9_-]{1,40}",label): raise ValueError("Invalid project label")
        name=json.loads((PROJECT/label/"input.json").read_text())["name"]
        os.environ.pop("GH_TOKEN",None)
        result=analyze(name,label,filt,query,limit,resume=True)
        if mode=="resume_test":
            assert any(x["kind"]=="constant" for x in read_tsv(result/"matches.tsv"))
            assert any(x["name"]=="cloud_probe" for x in read_tsv(result/"functions.tsv"))
            print("CROSS_RUNNER_RESTORE_PASSED",flush=True)
    elif mode in ("analyze","compare"):
        a=input_path(os.environ["INPUT_PATH"])
        language=os.getenv("RAW_LANGUAGE","")
        raw=(language,os.environ["RAW_BASE"],os.environ["RAW_ENTRY"],os.getenv("RAW_COMPILER","default")) if language else None
        ra=analyze(a,"a",filt,query,limit,raw)
        if mode=="compare":
            b=input_path(os.environ["COMPARE_PATH"])
            rb=analyze(b,"b",filt,query,limit,raw)
            compare(a,b,ra,rb)
    else: raise ValueError("Unknown mode")
    package()

if __name__=="__main__": main()
