# tvbox.spec
a = Analysis(
    ['tvbox_server_qianwen.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[
        '_cffi_backend',  # 解决 curl_cffi 打包后 ModuleNotFoundError[reference:2]
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='TvBoxHelper_qianwen',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,  # 建议保留控制台以便查看日志，或改为 False
)
