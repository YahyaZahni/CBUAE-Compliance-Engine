"""Shared configuration: thresholds, institution model (assets, entitlements, roles, zones, services)."""
from dataclasses import dataclass, field
from pathlib import Path

import pandas as pd
import yaml

ROOT = Path(__file__).resolve().parents[1]


def opa_path() -> str:
    """Open Policy Agent binary: $OPA_BIN, else bin/opa(.exe) in the project, else `opa` on the PATH."""
    import os
    import shutil
    if os.environ.get("OPA_BIN"):
        return os.environ["OPA_BIN"]
    for name in ("opa", "opa.exe"):
        if (ROOT / "bin" / name).exists():
            return str(ROOT / "bin" / name)
    found = shutil.which("opa")
    if not found:
        raise FileNotFoundError("Open Policy Agent not found: put it in bin/, on the PATH, or set OPA_BIN")
    return found
CONFIG = ROOT / "config"


@dataclass
class Config:
    settings: dict
    assets: pd.DataFrame
    entitlements: pd.DataFrame
    roles: dict              # role -> set(baseline entitlements)
    role_function: dict      # role -> business function
    sod_pairs: list          # [(a, b, reason)]
    zone_matrix: dict        # (src_zone, dst_zone) -> set(services)
    services: pd.DataFrame
    port_service: dict = field(default_factory=dict)   # (protocol, port) -> service

    @property
    def ent_asset(self):
        return dict(zip(self.entitlements.entitlement, self.entitlements.asset_id))

    @property
    def ent_privileged(self):
        return dict(zip(self.entitlements.entitlement, self.entitlements.privileged))

    @property
    def cia_assets(self):
        return set(self.assets.loc[self.assets.critical_information_asset, "asset_id"])

    @property
    def asset_zone(self):
        return dict(zip(self.assets.asset_id, self.assets.zone))

    @property
    def asset_owner_role(self):
        return dict(zip(self.assets.asset_id, self.assets.owner_role))

    @property
    def cleartext_ndpi(self):
        return set(self.services.loc[~self.services.encrypted, "ndpi_id"].astype(int))

    def directory_logon(self, auth: pd.DataFrame) -> pd.Series:
        """Routine Kerberos/LDAP authentication to a directory asset (settings.directory_assets) from outside the
        MANAGEMENT zone. It is not use of the asset's data, so it is ignored for AC-05 usage and AC-08 access."""
        directory = set(self.settings.get("directory_assets", []))
        src_zone = auth.src_asset.map(self.asset_zone).fillna("USER")
        return auth.dst_asset.isin(directory) & src_zone.ne("MANAGEMENT")

    def conflicts(self, ent):
        return {b for a, b, _ in self.sod_pairs if a == ent} | {a for a, b, _ in self.sod_pairs if b == ent}


def load_config(config_dir: Path = CONFIG) -> Config:
    settings = yaml.safe_load((config_dir / "settings.yaml").read_text(encoding="utf-8"))
    assets = pd.read_csv(config_dir / "assets.csv")
    assets["critical_information_asset"] = assets.critical_information_asset.astype(bool)
    ents = pd.read_csv(config_dir / "entitlements.csv")
    ents["privileged"] = ents.privileged.astype(bool)
    roles_df = pd.read_csv(config_dir / "role_entitlements.csv")
    roles = {r.role: set(r.baseline_entitlements.split(";")) for r in roles_df.itertuples()}
    role_function = dict(zip(roles_df.role, roles_df.function))
    sod = [tuple(r) for r in pd.read_csv(config_dir / "sod_matrix.csv").itertuples(index=False)]
    zm = {(r.src_zone, r.dst_zone): set(r.services.split(";")) for r in pd.read_csv(config_dir / "zone_matrix.csv").itertuples()}
    services = pd.read_csv(config_dir / "services.csv")
    services["encrypted"] = services.encrypted.astype(bool)
    services["prohibited"] = services.prohibited.astype(bool)
    cfg = Config(settings, assets, ents, roles, role_function, sod, zm, services)
    cfg.port_service = {(r.protocol, int(r.port)): r.service for r in services.itertuples()}
    # sanity: every baseline / entitlement must reference known objects
    known = set(ents.entitlement)
    for role, es in roles.items():
        unknown = es - known
        assert not unknown, f"role {role} references unknown entitlements {unknown}"
        for e in es:
            assert not (cfg.conflicts(e) & es), f"role {role} baseline violates SoD on {e}"
    assert set(ents.asset_id) <= set(assets.asset_id), "entitlement references unknown asset"
    return cfg


def business_deadline(ts: pd.Timestamp, business_days: int) -> pd.Timestamp:
    """End of the n-th business day after ts (UAE working week Monday to Friday)."""
    d = ts.normalize()
    added = 0
    while added < business_days:
        d += pd.Timedelta(days=1)
        if d.weekday() < 5:
            added += 1
    return d + pd.Timedelta(days=1) - pd.Timedelta(milliseconds=1)
