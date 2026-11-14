#!/usr/bin/env python3

import argparse
import os
import shutil
import sys
from concurrent.futures import ProcessPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

from evtx import PyEvtxParser

try:
    import orjson

    def loads(s):
        return orjson.loads(s)

    def dumps(o):
        return orjson.dumps(o).decode("utf-8")
except ImportError:
    import json

    def loads(s):
        return json.loads(s)

    def dumps(o):
        return json.dumps(o, ensure_ascii=False, separators=(",", ":"))


def norm_ts(value: str) -> str:
    """Normalise en AAAA-MM-JJTHH:MM:SS.ffffffZ (toujours 6 décimales)."""
    value = value.replace(" UTC", "").rstrip("Z").replace(" ", "T")
    date, _, frac = value.partition(".")
    return f"{date}.{(frac + '000000')[:6]}Z"


def prune(o):
    """Supprime les valeurs vides (null, "", [], {})."""
    if isinstance(o, dict):
        o = {k: prune(v) for k, v in o.items()}
        return {k: v for k, v in o.items() if v not in (None, "", [], {})}
    if isinstance(o, list):
        o = [prune(v) for v in o]
        return [v for v in o if v not in (None, "", [], {})]
    return o


def strip_xmlns(o):
    """Retire les attributs xmlns (bruit) ; les #attributes vides sont ensuite supprimés par prune()."""
    if isinstance(o, dict):
        out = {}
        for k, v in o.items():
            v = strip_xmlns(v)
            if k == "#attributes" and isinstance(v, dict):
                v = {a: b for a, b in v.items() if a != "xmlns"}
            out[k] = v
        return out
    if isinstance(o, list):
        return [strip_xmlns(v) for v in o]
    return o


def attrs(node) -> dict:
    """Attributs XML d'un nœud ({"#attributes": {...}}) ou {}."""
    return (node.get("#attributes") or {}) if isinstance(node, dict) else {}


def flatten_system(system: dict) -> dict:
    """Aplatit <System> : un champ par information, sans #attributes imbriqués."""
    eid = system.get("EventID")
    qualifiers = None
    if isinstance(eid, dict):
        qualifiers = attrs(eid).get("Qualifiers")
        eid = eid.get("#text")
    out = {
        "Provider": attrs(system.get("Provider")).get("Name"),
        "ProviderGuid": attrs(system.get("Provider")).get("Guid"),
        "EventID": eid,
        "Qualifiers": qualifiers,
    }
    for key in ("Version", "Level", "Task", "Opcode", "Keywords",
                "EventRecordID", "Channel", "Computer"):
        out[key] = system.get(key)
    out["ProcessID"] = attrs(system.get("Execution")).get("ProcessID")
    out["ThreadID"] = attrs(system.get("Execution")).get("ThreadID")
    out["UserID"] = attrs(system.get("Security")).get("UserID")
    out["ActivityID"] = attrs(system.get("Correlation")).get("ActivityID")
    return out


def clean_data(node):
    """EventData : remplace {"Data": {"#text": [...]}} par {"Data": [...]}."""
    if isinstance(node, dict):
        data = node.get("Data")
        if isinstance(data, dict) and "#text" in data:
            node = {**node, "Data": data["#text"]}
    return node


def build_line(record: dict, source_name: str, hec: bool) -> str:
    event = loads(record["data"]).get("Event", {})
    event.pop("#attributes", None)  # retire le xmlns inutile
    system = event.pop("System", None) or {}

    created = attrs(system.get("TimeCreated")).get("SystemTime") or record.get("timestamp", "")
    ts = norm_ts(str(created))

    fields = flatten_system(system)
    body = {k: (clean_data(v) if k == "EventData" else v) for k, v in event.items()}
    doc = prune(strip_xmlns({"SourceFile": source_name, **fields, **body}))

    if hec:
        try:
            epoch = datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(timezone.utc).timestamp()
        except ValueError:
            epoch = None
        return dumps(prune({
            "time": epoch,
            "host": fields.get("Computer"),
            "source": source_name,
            "sourcetype": "evtx_json",
            "event": doc,
        }))

    return dumps({"timestamp": ts, **doc})


def convert_file(job):
    """Convertit un .evtx vers un fichier temporaire (exécuté dans un process worker)."""
    evtx_path, tmp_path, threads, hec = job
    name = Path(evtx_path).name
    ok = errors = 0
    batch = []

    try:
        records = iter(PyEvtxParser(evtx_path, number_of_threads=threads).records_json())
    except Exception as exc:
        return name, 0, 0, None, f"fichier illisible : {exc}"

    with open(tmp_path, "w", encoding="utf-8", newline="\n", buffering=1 << 20) as out:
        while True:
            try:
                record = next(records)
            except StopIteration:
                break
            except Exception:
                errors += 1
                continue

            try:
                batch.append(build_line(record, name, hec))
                ok += 1
            except Exception:
                errors += 1
                continue

            if len(batch) >= 5000:
                out.write("\n".join(batch) + "\n")
                batch.clear()

        if batch:
            out.write("\n".join(batch) + "\n")

    return name, ok, errors, tmp_path, None


def main():
    parser = argparse.ArgumentParser(description="Fusion de .evtx en JSON (NDJSON) pour Splunk")
    parser.add_argument("-d", "--directory", default=".", help="Répertoire contenant les .evtx")
    parser.add_argument("-o", "--output", default="merged_events.json", help="Fichier JSON de sortie")
    parser.add_argument("-r", "--recursive", action="store_true", help="Inclure les sous-répertoires")
    parser.add_argument("-j", "--jobs", type=int, default=os.cpu_count() or 4,
                        help="Nombre de fichiers traités en parallèle")
    parser.add_argument("--hec", action="store_true",
                        help="Format HTTP Event Collector (time/host/source/sourcetype/event)")
    args = parser.parse_args()

    base = Path(args.directory)
    pattern = "**/*" if args.recursive else "*"
    files = sorted(p for p in base.glob(pattern) if p.is_file() and p.suffix.lower() == ".evtx")
    if not files:
        sys.exit(f"Aucun fichier .evtx trouvé dans {base.resolve()}")

    out_path = Path(args.output).resolve()
    tmp_dir = out_path.parent
    threads = 0 if len(files) == 1 else 1
    jobs = [(str(f), str(tmp_dir / f".tmp_{i}.part"), threads, args.hec) for i, f in enumerate(files)]

    total_ok = total_err = 0
    parts = []
    with ProcessPoolExecutor(max_workers=max(1, args.jobs)) as pool:
        for name, ok, err, tmp, problem in pool.map(convert_file, jobs):
            if problem:
                print(f"[!] {name} : {problem}", file=sys.stderr)
                continue
            print(f"[+] {name} : {ok} événements ({err} erreurs)")
            total_ok += ok
            total_err += err
            parts.append(tmp)

    with open(out_path, "wb") as out:
        for tmp in parts:
            with open(tmp, "rb") as src:
                shutil.copyfileobj(src, out, 1 << 24)
            os.remove(tmp)

    print(f"\nTerminé : {total_ok} événements dans {out_path} "
          f"({total_err} erreurs, {len(parts)} fichiers)")


if __name__ == "__main__":
    main()
