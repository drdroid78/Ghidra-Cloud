"""Owner-only GitHub issue request. JSON data, never shell or executable code."""
import json, os, re
from pathlib import Path
event=json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
issue=event["issue"]
if issue["user"]["id"]!=62127032 or event["sender"]["id"]!=62127032 or issue["author_association"]!="OWNER":
    raise SystemExit("Unauthorized request")
target=os.environ["REQUEST_KIND"]
if issue["title"]!=("Ghidra Toolbox request" if target=="toolbox" else "Ghidra Cloud request"):
    raise SystemExit("Invalid title")
data=json.loads(issue["body"] or "")
common={"mode":"MODE","binary_path":"INPUT_PATH","query":"QUERY","max_functions":"LIMIT","raw_language":"RAW_LANGUAGE","raw_base":"RAW_BASE","raw_entry":"RAW_ENTRY","raw_compiler":"RAW_COMPILER"}
mapping=common|({"analyzers":"ANALYZERS","rules_path":"RULES_PATH","raw_arch":"RAW_ARCH"} if target=="toolbox" else {"compare_path":"COMPARE_PATH","function_filter":"FILTER","resume_run":"RESUME_RUN","resume_label":"RESUME_LABEL"})
if not isinstance(data,dict) or set(data)-set(mapping)-({"source_ref"} if target=="ghidra" else set()):raise SystemExit("Unexpected fields")
if "source_ref" in data and (target!="ghidra" or data["source_ref"]!="tmp-libstardroid-analysis"):raise SystemExit("Unapproved source_ref")
mode=data.get("mode")
if mode not in (["selftest","analyze"] if target=="toolbox" else ["selftest","analyze","compare","resume"]):raise SystemExit("Invalid mode")
if mode in ("analyze","compare") and not data.get("binary_path"):raise SystemExit("binary_path required")
if mode=="compare" and not data.get("compare_path"):raise SystemExit("compare_path required")
if mode=="resume" and not data.get("resume_run"):raise SystemExit("resume_run required")
for k,v in data.items():
    if k=="source_ref": continue
    if not isinstance(v,str) or len(v)>512 or any(ord(c)<32 or ord(c)==127 for c in v):raise SystemExit("Invalid string value")
    if k.endswith("_path") and (Path(v).is_absolute() or ".." in Path(v).parts or v.startswith("-")):raise SystemExit("Repository-relative public path required")
    if k=="max_functions" and (not v.isdecimal() or not 1<=int(v)<=5000):raise SystemExit("Invalid limit")
    if k=="resume_run" and not re.fullmatch(r"[1-9][0-9]{0,19}",v):raise SystemExit("Invalid run ID")
with open(os.environ["GITHUB_ENV"],"a") as f:
    for k,v in data.items():
        if k!="source_ref":f.write(mapping[k]+"="+v+"\n")
with open(os.environ["GITHUB_OUTPUT"],"a") as f:
    f.write("mode="+mode+"\n")
    if "source_ref" in data:f.write("source_ref="+data["source_ref"]+"\n")
print("OWNER_REQUEST_OK issue="+str(issue["number"])+" mode="+mode)
