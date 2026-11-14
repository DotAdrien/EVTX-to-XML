import argparse
import os
import re
import shutil
import sys
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from xml.sax.saxutils import escape

from evtx import PyEvtxParser

BETWEEN_TAGS = re.compile(r">\s+<")


def convert_file(job):
    """Convertit un .evtx vers un fichier temporaire. Exécuté dans un process worker."""
    evtx_path, tmp_path, threads = job
    name = Path(evtx_path).name
    tag = f"<SourceFile>{escape(name)}</SourceFile></Event>"
    ok = errors = 0
    batch = []

    try:
        records = iter(PyEvtxParser(evtx_path, number_of_threads=threads).records())
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

            xml = record["data"]
            xml = xml[xml.find("<Event"):]                 # retire <?xml ...?>
            xml = BETWEEN_TAGS.sub("><", xml)              # retire l'indentation
            xml = xml.replace("\r", " ").replace("\n", " ")  # 1 événement = 1 ligne
            batch.append(xml.replace("</Event>", tag))
            ok += 1

            if len(batch) >= 5000:
                out.write("\n".join(batch) + "\n")
                batch.clear()

        if batch:
            out.write("\n".join(batch) + "\n")

    return name, ok, errors, tmp_path, None


def main():
    parser = argparse.ArgumentParser(description="Fusion rapide de .evtx en XML pour Splunk")
    parser.add_argument("-d", "--directory", default=".", help="Répertoire contenant les .evtx")
    parser.add_argument("-o", "--output", default="merged_events.xml", help="Fichier XML de sortie")
    parser.add_argument("-r", "--recursive", action="store_true", help="Inclure les sous-répertoires")
    parser.add_argument("-j", "--jobs", type=int, default=os.cpu_count() or 4,
                        help="Nombre de fichiers traités en parallèle")
    parser.add_argument("--wrap", action="store_true",
                        help="Entourer le tout d'une racine <Events> (XML bien formé)")
    args = parser.parse_args()

    base = Path(args.directory)
    pattern = "**/*" if args.recursive else "*"
    files = sorted(p for p in base.glob(pattern) if p.is_file() and p.suffix.lower() == ".evtx")
    if not files:
        sys.exit(f"Aucun fichier .evtx trouvé dans {base.resolve()}")

    out_path = Path(args.output).resolve()
    tmp_dir = out_path.parent
    # Un seul fichier : le parseur peut utiliser tous les cœurs ; sinon 1 thread par fichier
    threads = 0 if len(files) == 1 else 1
    jobs = [(str(f), str(tmp_dir / f".tmp_{i}.part"), threads) for i, f in enumerate(files)]

    total_ok = total_err = 0
    parts = []
    with ProcessPoolExecutor(max_workers=max(1, args.jobs)) as pool:
        for name, ok, err, tmp, problem in pool.map(convert_file, jobs):  # ordre conservé
            if problem:
                print(f"[!] {name} : {problem}", file=sys.stderr)
                continue
            print(f"[+] {name} : {ok} événements ({err} erreurs)")
            total_ok += ok
            total_err += err
            parts.append(tmp)

    with open(out_path, "wb") as out:
        if args.wrap:
            out.write(b'<?xml version="1.0" encoding="UTF-8"?>\n<Events>\n')
        for tmp in parts:
            with open(tmp, "rb") as src:
                shutil.copyfileobj(src, out, 1 << 24)
            os.remove(tmp)
        if args.wrap:
            out.write(b"</Events>\n")

    print(f"\nTerminé : {total_ok} événements dans {out_path} "
          f"({total_err} erreurs, {len(parts)} fichiers)")


if __name__ == "__main__":
    main()
