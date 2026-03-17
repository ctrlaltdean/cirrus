# PyInstaller spec file for CIRRUS — compatible with PyInstaller 6.x
# Build: pyinstaller cirrus.spec
# Output: dist/cirrus  (or dist/cirrus.exe on Windows)

from pathlib import Path

a = Analysis(
    ["cirrus/cli.py"],
    pathex=[str(Path(".").resolve())],
    binaries=[],
    datas=[],
    hiddenimports=[
        # MSAL internals
        "msal",
        "msal.application",
        "msal.authority",
        "msal.token_cache",
        # Requests / urllib3 / certs
        "requests",
        "urllib3",
        "certifi",
        # Typer / Rich
        "typer",
        "rich",
        "rich.console",
        "rich.panel",
        "rich.table",
        "rich.progress",
        "rich.prompt",
        "rich.text",
        # Pydantic
        "pydantic",
        # cirrus — core
        "cirrus",
        "cirrus.auth.authenticator",
        "cirrus.audit.logger",
        "cirrus.output.case",
        "cirrus.output.writer",
        "cirrus.utils.helpers",
        # cirrus — collectors
        "cirrus.collectors.base",
        "cirrus.collectors.signin_logs",
        "cirrus.collectors.audit_logs",
        "cirrus.collectors.unified_audit",
        "cirrus.collectors.mailbox_rules",
        "cirrus.collectors.mail_forwarding",
        "cirrus.collectors.oauth_grants",
        "cirrus.collectors.conditional_access",
        "cirrus.collectors.mfa_methods",
        "cirrus.collectors.risky_users",
        "cirrus.collectors.users",
        "cirrus.collectors.service_principals",
        # cirrus — workflows
        "cirrus.workflows.base",
        "cirrus.workflows.bec",
        "cirrus.workflows.full",
        # DNS (dnspython)
        "dns",
        "dns.resolver",
        "dns.rdatatype",
        "dns.exception",
        "dns.rdtypes",
        "dns.rdtypes.ANY",
        "dns.rdtypes.IN",
        # cirrus — utils
        "cirrus.utils.dns_checker",
        "cirrus.utils.exchange_ps",
        "cirrus.utils.teams_ps",
        "cirrus.utils.sharepoint_ps",
        "cirrus.utils.deps",
        # cirrus — compliance
        "cirrus.compliance",
        "cirrus.compliance.base",
        "cirrus.compliance.context",
        "cirrus.compliance.runner",
        "cirrus.compliance.report",
        "cirrus.compliance.checks",
        "cirrus.compliance.checks.identity",
        "cirrus.compliance.checks.admin",
        "cirrus.compliance.checks.exchange",
        "cirrus.compliance.checks.teams_sharepoint",
        "cirrus.compliance.checks.logging",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "tkinter",
        "matplotlib",
        "numpy",
        "pandas",
        "scipy",
        "PIL",
        "IPython",
        "jupyter",
        "test",
        "unittest",
    ],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="cirrus",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,          # UPX not available on all CI runners — disabled
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,       # CLI tool — keep console window
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
