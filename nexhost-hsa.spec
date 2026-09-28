# PyInstaller specification for the desktop entry point.
from PyInstaller.utils.hooks import collect_submodules

hiddenimports = collect_submodules("sqlalchemy")
a = Analysis(["app/main.py"], pathex=[], binaries=[], datas=[], hiddenimports=hiddenimports)
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, a.binaries, a.datas, [], name="nexhost-hsa", console=False)
