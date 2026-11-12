"""Loaders for the public datasets, in their published file formats.

Expected layout under a raw directory (see README for download links):
  cert/LDAP/YYYY-MM.csv      CERT Insider Threat Test Dataset r6.2 (Lindauer, 2020): monthly directory snapshots
  cert/logon.csv             CERT r6.2 workstation logon/logoff events
  lanl/auth.txt              LANL "Comprehensive, multi-source cyber-security events" (Kent, 2015), auth.txt
  netflow/*.csv              UQ NetFlow v3 datasets (Sarhan et al.; v3 adds flow timestamps)
  iam/                       Institution state not published in any public dataset (simulated, see simulate_state.py)

Only the columns listed in REQUIRED are used; extra columns are ignored, so minor version differences load.
"""
from pathlib import Path

import pandas as pd

REQUIRED = {
    "cert_ldap": ["user_id", "role"],
    "cert_logon": ["id", "date", "user", "pc", "activity"],
    "netflow_v3": ["FLOW_START_MILLISECONDS", "FLOW_END_MILLISECONDS", "IPV4_SRC_ADDR", "L4_SRC_PORT",
                   "IPV4_DST_ADDR", "L4_DST_PORT", "PROTOCOL", "L7_PROTO", "IN_BYTES", "IN_PKTS",
                   "OUT_BYTES", "OUT_PKTS", "TCP_FLAGS", "FLOW_DURATION_MILLISECONDS"],
}
LANL_AUTH_COLS = ["time", "src_user", "dst_user", "src_computer", "dst_computer", "auth_type", "logon_type",
                  "auth_orientation", "outcome"]


def _need(df, kind, path):
    missing = [c for c in REQUIRED[kind] if c not in df.columns]
    if missing:
        raise ValueError(f"{path}: missing columns {missing} for {kind}")


def load_cert_ldap(ldap_dir: Path) -> pd.DataFrame:
    """Monthly LDAP snapshots -> one row per (month, user). Month taken from the file name YYYY-MM.csv."""
    frames = []
    for p in sorted(Path(ldap_dir).glob("*.csv")):
        df = pd.read_csv(p, dtype=str)
        _need(df, "cert_ldap", p)
        df["month"] = pd.Period(p.stem, freq="M")
        frames.append(df)
    if not frames:
        raise FileNotFoundError(f"no LDAP files in {ldap_dir}")
    return pd.concat(frames, ignore_index=True)


def people_timeline(ldap: pd.DataFrame) -> pd.DataFrame:
    """Joiners and leavers from monthly snapshots.

    start = first day of the first month the user appears; termination = last day of the last month the user
    appears, if that month is not the final snapshot (CERT gives month granularity only; documented assumption).
    The role is the most recent one."""
    last_month = ldap.month.max()
    g = ldap.sort_values("month").groupby("user_id")
    out = pd.DataFrame({"first": g.month.min(), "last": g.month.max(), "role": g.role.last()})
    for col in ("employee_name", "department", "functional_unit", "supervisor"):
        if col in ldap.columns:
            out[col] = g[col].last()
    out["start"] = out["first"].dt.start_time
    out["termination"] = out["last"].dt.end_time.dt.normalize().where(out["last"] < last_month)
    return out.drop(columns=["first", "last"]).reset_index()


def load_cert_logon(path: Path) -> pd.DataFrame:
    df = pd.read_csv(path, dtype=str)
    _need(df, "cert_logon", path)
    df["time"] = pd.to_datetime(df["date"], format="%m/%d/%Y %H:%M:%S")
    return df


def load_lanl_auth(path: Path, epoch: pd.Timestamp) -> pd.DataFrame:
    """LANL auth.txt has no header; time is seconds from the start of the collection, re-based onto `epoch`."""
    df = pd.read_csv(path, header=None, names=LANL_AUTH_COLS, dtype=str)
    df["time"] = epoch + pd.to_timedelta(df["time"].astype(int), unit="s")
    return df


def load_netflow_v3(path: Path) -> pd.DataFrame:
    df = pd.read_csv(path)
    _need(df, "netflow_v3", path)
    # L7_PROTO is "master.app" in nDPI notation (e.g. 91.126 = TLS.Google); the master protocol is the integer part
    df["ndpi_master"] = df["L7_PROTO"].astype(float).astype(int)
    return df
