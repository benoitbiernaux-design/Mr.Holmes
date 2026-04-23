#!/usr/bin/env python3
import argparse
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Tuple

import dns.resolver
from fpdf import FPDF

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", value)


def query_txt(name: str) -> List[str]:
    try:
        answers = dns.resolver.resolve(name, "TXT")
        rows = []
        for rdata in answers:
            rows.append("".join(part.decode() if isinstance(part, bytes) else str(part) for part in rdata.strings))
        return rows
    except Exception:
        return []


def query_mx(domain: str) -> List[Tuple[int, str]]:
    try:
        answers = dns.resolver.resolve(domain, "MX")
        return sorted([(r.preference, str(r.exchange).rstrip('.')) for r in answers], key=lambda x: x[0])
    except Exception:
        return []


def query_a(domain: str) -> List[str]:
    try:
        answers = dns.resolver.resolve(domain, "A")
        return [r.address for r in answers]
    except Exception:
        return []


def run_whois(domain: str) -> str:
    try:
        result = subprocess.run(["whois", domain], capture_output=True, text=True, check=False, timeout=30)
        text = (result.stdout or "")[:12000]
        return text.strip() or "No WHOIS output returned."
    except Exception as exc:
        return f"WHOIS unavailable: {exc}"


def extract_spf(txt_records: List[str]) -> List[str]:
    return [r for r in txt_records if r.lower().startswith("v=spf1")]


def extract_dmarc(domain: str) -> List[str]:
    return query_txt(f"_dmarc.{domain}")


def common_dkim(domain: str) -> List[str]:
    selectors = ["default", "selector1", "selector2", "google", "k1", "smtp", "mail"]
    found = []
    for selector in selectors:
        rows = query_txt(f"{selector}._domainkey.{domain}")
        if rows:
            found.append(f"{selector}: " + " | ".join(rows))
    return found


class ReportPDF(FPDF):
    def header(self):
        self.set_font("Helvetica", "B", 14)
        self.cell(0, 10, "Email & Domain Technical Report", new_x="LMARGIN", new_y="NEXT")
        self.set_font("Helvetica", "", 9)
        self.cell(0, 6, datetime.now(timezone.utc).strftime("Generated on %Y-%m-%d %H:%M UTC"), new_x="LMARGIN", new_y="NEXT")
        self.ln(2)

    def footer(self):
        self.set_y(-12)
        self.set_font("Helvetica", "I", 8)
        self.cell(0, 10, f"Page {self.page_no()}", align="C")

    def section(self, title: str):
        self.set_font("Helvetica", "B", 12)
        self.cell(0, 8, title, new_x="LMARGIN", new_y="NEXT")
        self.set_font("Helvetica", "", 10)

    def lines(self, items: List[str]):
        if not items:
            self.multi_cell(0, 6, "No data found.")
            return
        for item in items:
            self.multi_cell(0, 6, f"- {item}")
        self.ln(1)

    def block(self, text: str):
        self.multi_cell(0, 5, text)
        self.ln(1)


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate a technical PDF report for an email/domain.")
    parser.add_argument("email", help="Email address to analyze")
    parser.add_argument("--out-dir", default="artifacts/email-report", help="Output directory")
    args = parser.parse_args()

    email = args.email.strip()
    out_dir = Path(args.out_dir)
    ensure_dir(out_dir)

    valid = bool(EMAIL_RE.match(email))
    domain = email.split("@", 1)[1].lower() if "@" in email else ""
    domain_txt = query_txt(domain) if domain else []
    mx = query_mx(domain) if domain else []
    a_records = query_a(domain) if domain else []
    spf = extract_spf(domain_txt)
    dmarc = extract_dmarc(domain) if domain else []
    dkim = common_dkim(domain) if domain else []
    whois_text = run_whois(domain) if domain else "WHOIS unavailable because the domain could not be parsed."

    summary = []
    summary.append(f"Email format valid: {'Yes' if valid else 'No'}")
    summary.append(f"Domain parsed: {domain or 'No'}")
    summary.append(f"MX records found: {len(mx)}")
    summary.append(f"SPF record found: {'Yes' if spf else 'No'}")
    summary.append(f"DMARC record found: {'Yes' if dmarc else 'No'}")
    summary.append(f"Common DKIM selectors found: {len(dkim)}")

    txt_report = out_dir / f"{safe_name(email)}_report.txt"
    pdf_report = out_dir / f"{safe_name(email)}_report.pdf"

    with txt_report.open("w", encoding="utf-8") as f:
        f.write("Email & Domain Technical Report\n")
        f.write(f"Generated: {datetime.now(timezone.utc).isoformat()}\n\n")
        f.write(f"Email: {email}\n")
        f.write(f"Valid format: {'Yes' if valid else 'No'}\n")
        f.write(f"Domain: {domain or 'N/A'}\n\n")
        f.write("Summary\n")
        for row in summary:
            f.write(f"- {row}\n")
        f.write("\nMX Records\n")
        for pref, exch in mx:
            f.write(f"- {pref} {exch}\n")
        f.write("\nA Records\n")
        for row in a_records:
            f.write(f"- {row}\n")
        f.write("\nSPF\n")
        for row in spf:
            f.write(f"- {row}\n")
        f.write("\nDMARC\n")
        for row in dmarc:
            f.write(f"- {row}\n")
        f.write("\nCommon DKIM selectors\n")
        for row in dkim:
            f.write(f"- {row}\n")
        f.write("\nWHOIS\n")
        f.write(whois_text)
        f.write("\n")

    pdf = ReportPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.section("Target")
    pdf.lines([f"Email: {email}", f"Domain: {domain or 'N/A'}", f"Valid format: {'Yes' if valid else 'No'}"])
    pdf.section("Summary")
    pdf.lines(summary)
    pdf.section("MX Records")
    pdf.lines([f"{pref} {exch}" for pref, exch in mx])
    pdf.section("A Records")
    pdf.lines(a_records)
    pdf.section("SPF")
    pdf.lines(spf)
    pdf.section("DMARC")
    pdf.lines(dmarc)
    pdf.section("Common DKIM selectors")
    pdf.block("This check only tests a few common selectors. Absence here does not prove that DKIM is not configured.")
    pdf.lines(dkim)
    pdf.section("WHOIS")
    pdf.block(whois_text[:7000])
    pdf.output(str(pdf_report))

    print(f"TXT report: {txt_report}")
    print(f"PDF report: {pdf_report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
