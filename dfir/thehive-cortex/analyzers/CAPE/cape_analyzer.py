#!/usr/bin/env python3
"""Cortex analyzer: submit a file to the lab CAPEv2 sandbox and return a report summary."""
import time

import requests
from cortexutils.analyzer import Analyzer


class CapeAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.url = self.get_param("config.url", None, "CAPE URL is missing").rstrip("/")
        self.wait = int(self.get_param("config.timeout_minutes", 20)) * 60
        self.analysis_timeout = int(self.get_param("config.analysis_seconds", 120))

    def api(self, path, **kw):
        r = requests.request(kw.pop("method", "GET"), f"{self.url}/apiv2/{path}", timeout=60, **kw)
        r.raise_for_status()
        d = r.json()
        if d.get("error"):
            self.error(f"CAPE API error on {path}: {d.get('error_value') or d}")
        return d.get("data", d)

    def run(self):
        if self.data_type != "file":
            self.error("CAPE_File_Analysis only accepts files")
        path = self.get_param("file", None, "File is missing")
        name = self.get_param("filename", "sample")
        with open(path, "rb") as fh:
            data = self.api("tasks/create/file/", method="POST", files={"file": (name, fh)},
                            data={"timeout": self.analysis_timeout})
        task = data["task_ids"][0]

        deadline = time.time() + self.wait
        status = ""
        while time.time() < deadline:
            status = self.api(f"tasks/status/{task}/")
            if status in ("reported", "failed_analysis", "failed_processing", "failed_reporting"):
                break
            time.sleep(15)
        if status != "reported":
            self.error(f"CAPE task {task} ended with status '{status}' (or timed out)")

        rep = self.api(f"tasks/get/report/{task}/json/")
        if isinstance(rep, dict) and "report" in rep:
            rep = rep["report"]
        info = rep.get("info", {})
        sigs = [{"name": s.get("name"), "severity": s.get("severity"), "description": s.get("description")}
                for s in rep.get("signatures", [])]
        net = rep.get("network", {})
        families = sorted({d.get("family") for d in rep.get("detections", []) or [] if isinstance(d, dict) and d.get("family")}
                          | ({rep.get("malfamily")} if rep.get("malfamily") else set()))
        self.report({
            "task_id": task,
            "cape_url": f"{self.url}/analysis/{task}/",
            "malscore": rep.get("malscore", 0),
            "families": families,
            "duration": info.get("duration"),
            "machine": (info.get("machine") or {}).get("name"),
            "signatures": sigs,
            "hosts": [h.get("ip") if isinstance(h, dict) else h for h in net.get("hosts", [])][:100],
            "domains": [d.get("domain") for d in net.get("domains", []) if d.get("domain")][:100],
            "dropped": [{"name": d.get("name"), "sha256": d.get("sha256")} for d in rep.get("dropped", [])][:100],
            "processes": [p.get("process_name") for p in (rep.get("behavior") or {}).get("processes", [])][:100],
        })

    def summary(self, raw):
        score = float(raw.get("malscore") or 0)
        level = "malicious" if score >= 7 else "suspicious" if score >= 4 else "safe"
        taxes = [self.build_taxonomy(level, "CAPE", "Score", f"{score:.1f}/10")]
        for fam in raw.get("families", [])[:3]:
            taxes.append(self.build_taxonomy("malicious", "CAPE", "Family", fam))
        return {"taxonomies": taxes}

    def artifacts(self, raw):
        out = [self.build_artifact("domain", d) for d in raw.get("domains", [])]
        out += [self.build_artifact("ip", h) for h in raw.get("hosts", []) if h]
        out += [self.build_artifact("hash", d["sha256"]) for d in raw.get("dropped", []) if d.get("sha256")]
        return out


if __name__ == "__main__":
    CapeAnalyzer().run()
