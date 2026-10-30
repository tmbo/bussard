# /// script
# requires-python = ">=3.10"
# dependencies = ["paramiko"]
# ///
"""Hash and sign a fabricated .knxprod with ETS's own signing library, in the VM (epic #596).

    uv run tools/ets-sweep/synthetic/sign.py <in.knxprod> [<out.knxprod>] [--recompile] [--keep-master]
    uv run tools/ets-sweep/synthetic/sign.py --dir-only <in.knxprod> [<out>]  # directory signature only
    uv run tools/ets-sweep/synthetic/sign.py --verify <file.knxprod>   # the library's verdict, no change

Uploads `signer.cs` and the product to `C:\\Users\\macremote\\ets-sweep\\signer\\`,
compiles the signer with the .NET Framework `csc.exe` when its source changed
(no reference to ETS at compile time: the signer loads `Knx.Ets.XmlSigning.dll`
from the ETS 6 folder and calls it by reflection), runs it, and downloads the
signed file (default: `<in>-signed.knxprod`). An archive whose
`knx_master.xml` carries no `<MasterData>` (the stub `<KNX/>` of the synthetic
catalogue) gets ETS's own master data from the VM (`VM_MASTER`) in its place:
ETS 6.4 refuses the stub ("Die Eingabezeichenfolge hat das falsche Format", a
FormatException reading the master data version). `--keep-master` leaves the
archive's master as it is. See the README section
"Synthetic products: signing" for what the signer changes.

The signer is our own source; it only produces test data for the synthetic
catalogue and needs ETS installed where it runs.
"""
from __future__ import annotations

import hashlib
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import vm  # noqa: E402

HERE = Path(__file__).resolve().parent
REMOTE = vm.REMOTE_DIR + r"\signer"
CSC = r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
# ETS's own master data for schema 23 (project/23), the namespace of the synthetic products.
VM_MASTER = r"C:\ProgramData\KNX\XML\project-23\knx_master.xml"


def sftp_path(win: str) -> str:
    return win.replace("\\", "/")


def compile_signer(c, force: bool) -> None:
    """Upload signer.cs and compile it unless the VM already has this exact source built."""
    src = (HERE / "signer.cs").read_bytes()
    digest = hashlib.sha256(src).hexdigest()[:16]
    code, out = vm.run(c, f'type "{REMOTE}\\signer.sha"')
    if not force and code == 0 and out.strip() == digest:
        return
    vm.run(c, f'mkdir "{REMOTE}"')
    sftp = c.open_sftp()
    sftp.put(str(HERE / "signer.cs"), sftp_path(REMOTE + r"\signer.cs"))
    code, out = vm.run(
        c,
        f'cd /d "{REMOTE}" && "{CSC}" /nologo /out:signer.exe '
        "/r:System.IO.Compression.dll /r:System.IO.Compression.FileSystem.dll signer.cs",
        timeout=120,
    )
    if code != 0:
        raise SystemExit(f"csc failed:\n{out}")
    with sftp.open(sftp_path(REMOTE + r"\signer.sha"), "w") as f:
        f.write(digest)
    print("compiled signer.exe", digest)


def has_master_data(src: Path) -> bool:
    """Whether the archive's knx_master.xml is real master data, not the stub."""
    with zipfile.ZipFile(src) as z:
        try:
            return b"<MasterData" in z.read("knx_master.xml")[:4096]
        except KeyError:
            return False


def sign(src: Path, dst: Path, force_compile: bool = False, dir_only: bool = False,
         keep_master: bool = False) -> str:
    """Sign `src` into `dst` in the VM and return the signer's report."""
    c = vm.connect()
    compile_signer(c, force_compile)
    sftp = c.open_sftp()
    remote_in = REMOTE + r"\in.knxprod"
    remote_out = REMOTE + r"\out.knxprod"
    sftp.put(str(src), sftp_path(remote_in))
    flag = "--dir-only " if dir_only else ""
    if not keep_master and not has_master_data(src):
        flag = f'--master "{VM_MASTER}" ' + flag
    code, out = vm.run(c, f'cd /d "{REMOTE}" && signer.exe {flag}in.knxprod out.knxprod work', timeout=300)
    if code != 0:
        raise SystemExit(f"signer failed ({code}):\n{out}")
    dst.parent.mkdir(parents=True, exist_ok=True)
    sftp.get(sftp_path(remote_out), str(dst))
    return out


def verify(src: Path, force_compile: bool = False) -> str:
    """Return the signing library's check of every hash and signature in `src`."""
    c = vm.connect()
    compile_signer(c, force_compile)
    c.open_sftp().put(str(src), sftp_path(REMOTE + r"\verify.knxprod"))
    code, out = vm.run(c, f'cd /d "{REMOTE}" && signer.exe --verify verify.knxprod work-verify', timeout=300)
    if code != 0:
        raise SystemExit(f"signer --verify failed ({code}):\n{out}")
    return out


def main(argv: list[str]) -> int:
    force = "--recompile" in argv
    args = [a for a in argv if not a.startswith("--")]
    if not args:
        print(__doc__)
        return 2
    if "--verify" in argv:
        print(verify(Path(args[0]), force))
        return 0
    src = Path(args[0])
    dst = Path(args[1]) if len(args) > 1 else src.with_name(src.stem + "-signed.knxprod")
    print(sign(src, dst, force, "--dir-only" in argv, "--keep-master" in argv))
    print("wrote", dst)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
