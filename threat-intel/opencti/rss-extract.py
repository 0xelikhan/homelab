#!/usr/bin/env python3
"""rss-extract: attach each new RSS report's article to the report so ImportDocument links its entities.

import-external-reference saves the article on the external reference, not the report, so
ImportDocument never adds anything to the report. This fetches the Markdown copy and pushes it onto
the report itself. Run on VM 112 as root (systemd timer, every 30 minutes).

  rss-extract.py [--hours 6] [--max 80]
"""
import json, os, sys, time, urllib.parse, urllib.request, uuid

ENV = dict(l.split("=", 1) for l in open("/opt/opencti7/.env").read().splitlines() if "=" in l and not l.startswith("#"))
URL = "http://127.0.0.1:8080"
AUTH = {"Authorization": f"Bearer {ENV['OPENCTI_ADMIN_TOKEN']}"}
STATE = "/var/lib/rss-extract/done.txt"


def q(query, **v):
    req = urllib.request.Request(f"{URL}/graphql", json.dumps({"query": query, "variables": v}).encode(),
                                 {**AUTH, "Content-Type": "application/json"})
    r = json.load(urllib.request.urlopen(req, timeout=120))
    if r.get("errors"):
        raise RuntimeError(r["errors"][0]["message"])
    return r["data"]


def push_file(report_id, name, data):
    """GraphQL multipart upload (importPush) onto the report."""
    ops = {"query": "mutation($id:ID!,$file:Upload!){ stixCoreObjectEdit(id:$id){ importPush(file:$file){ id } } }",
           "variables": {"id": report_id, "file": None}}
    b = uuid.uuid4().hex
    body = (f"--{b}\r\nContent-Disposition: form-data; name=\"operations\"\r\n\r\n{json.dumps(ops)}\r\n"
            f"--{b}\r\nContent-Disposition: form-data; name=\"map\"\r\n\r\n{json.dumps({'0': ['variables.file']})}\r\n"
            f"--{b}\r\nContent-Disposition: form-data; name=\"0\"; filename=\"{name}\"\r\nContent-Type: text/markdown\r\n\r\n"
            ).encode() + data + f"\r\n--{b}--\r\n".encode()
    req = urllib.request.Request(f"{URL}/graphql", body, {**AUTH, "Content-Type": f"multipart/form-data; boundary={b}"})
    r = json.load(urllib.request.urlopen(req, timeout=120))
    if r.get("errors"):
        raise RuntimeError(r["errors"][0]["message"])


def main():
    args = sys.argv[1:]
    hours = int(args[args.index("--hours") + 1]) if "--hours" in args else 6
    limit = int(args[args.index("--max") + 1]) if "--max" in args else 80
    os.makedirs(os.path.dirname(STATE), exist_ok=True)
    done = set(open(STATE).read().split()) if os.path.exists(STATE) else set()

    conns = q("{ connectors { id name updated_at } }")["connectors"]
    ier = sorted([c for c in conns if c["name"] == "ImportExternalReference"], key=lambda c: c["updated_at"])[-1]["id"]
    since = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - hours * 3600))
    reports = q("""query($s:Any!){ reports(first:500,orderBy:created_at,orderMode:desc,filters:{mode:and,filterGroups:[],
                 filters:[{key:["created_at"],values:[$s],operator:gt,mode:or}]}){edges{node{
                 id importFiles(first:1){edges{node{id}}} externalReferences(first:1){edges{node{id url}}} }}} }""",
                s=since)["reports"]["edges"]

    todo = [r["node"] for r in reports if r["node"]["id"] not in done and not r["node"]["importFiles"]["edges"]
            and r["node"]["externalReferences"]["edges"]][:limit]
    ok = fail = 0
    for rep in todo:
        ref = rep["externalReferences"]["edges"][0]["node"]
        try:
            wid = q("mutation($id:ID!,$c:ID!){ externalReferenceEdit(id:$id){ askEnrichment(connectorId:$c){ id } } }",
                    id=ref["id"], c=ier)["externalReferenceEdit"]["askEnrichment"]["id"]
            # the file lands a little after the work reports complete, so wait for the file itself
            md, st = None, None
            for _ in range(24):
                time.sleep(5)
                files = q("query($id:String!){ externalReference(id:$id){ importFiles{edges{node{id name}}} } }",
                          id=ref["id"])["externalReference"]["importFiles"]["edges"]
                md = next((f["node"] for f in files if f["node"]["name"].endswith(".md")), None)
                if md:
                    break
                st = (q("query($id:ID!){ work(id:$id){ status } }", id=wid)["work"] or {}).get("status")
                if st == "failed":
                    break
            if not md:
                raise RuntimeError(f"no markdown after 120s ({st})")
            data = urllib.request.urlopen(urllib.request.Request(
                f"{URL}/storage/get/{urllib.parse.quote(md['id'], safe='')}", headers=AUTH), timeout=120).read()
            push_file(rep["id"], md["name"], data)
            ok += 1
        except Exception as e:
            fail += 1
            print(f"skip {ref['url'][:80]}: {str(e)[:100]}")
        done.add(rep["id"])
    open(STATE, "w").write("\n".join(sorted(done)))
    print(f"rss-extract: {len(todo)} reports, {ok} attached, {fail} skipped")


if __name__ == "__main__":
    main()
