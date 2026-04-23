#!/usr/bin/env python3
import argparse
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


def pdf_safe(text: str) -> str:
    replacements = {
        "•": "-",
        "—": "-",
        "–": "-",
        "“": '"',
        "”": '"',
        "’": "'",
        "…": "...",
    }
    for src, dst in replacements.items():
        text = text.replace(src, dst)
    return text


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


def status_text(value: bool) -> str:
    return "OK" if value else "Missing"


def summary_rows(valid: bool, domain: str, mx: List[Tuple[int, str]], spf: List[str], dmarc: List[str], dkim: List[str]) -> List[Tuple[str, str]]:
    return [
        ("Email format", "Valid" if valid else "Invalid"),
        ("Domain", domain or "Not parsed"),
        ("MX records", str(len(mx))),
        ("SPF", status_text(bool(spf))),
        ("DMARC", status_text(bool(dmarc))),
        ("Common DKIM selectors", str(len(dkim))),
    ]


class ReportPDF(FPDF):
    def _full_width(self) -> float:
        return self.w - self.l_margin - self.r_margin

    def _usable_two_col(self) -> Tuple[float, float]:
        total = self._full_width()
        label = total * 0.34
        value = total - label
        return label, value

    def header(self):
        self.set_fill_color(245, 247, 250)
        self.rect(self.l_margin, 10, self._full_width(), 22, style="F")
        self.set_xy(self.l_margin + 4, 14)
        self.set_text_color(25, 25, 25)
        self.set_font("Helvetica", "B", 16)
        self.cell(0, 8, "Email & Domain Technical Report", new_x="LMARGIN", new_y="NEXT")
        self.set_x(self.l_margin + 4)
        self.set_font("Helvetica", "", 9)
        self.set_text_color(90, 90, 90)
        self.cell(0, 5, datetime.now(timezone.utc).strftime("Generated on %Y-%m-%d %H:%M UTC"), new_x="LMARGIN", new_y="NEXT")
        self.ln(10)
        self.set_text_color(20, 20, 20)

    def footer(self):
        self.set_y(-12)
        self.set_draw_color(220, 220, 220)
        self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(110, 110, 110)
        self.cell(self._full_width(), 8, f"Page {self.page_no()}", align="C")
        self.set_text_color(20, 20, 20)

    def section(self, title: str, subtitle: str | None = None):
        self.ln(2)
        self.set_fill_color(237, 242, 247)
        self.rect(self.l_margin, self.get_y(), self._full_width(), 9, style="F")
        self.set_xy(self.l_margin + 3, self.get_y() + 1.5)
        self.set_font("Helvetica", "B", 12)
        self.cell(self._full_width() - 6, 6, pdf_safe(title), new_x="LMARGIN", new_y="NEXT")
        if subtitle:
            self.set_x(self.l_margin + 3)
            self.set_font("Helvetica", "", 9)
            self.set_text_color(95, 95, 95)
            self.multi_cell(self._full_width() - 6, 5, pdf_safe(subtitle))
            self.set_text_color(20, 20, 20)
        self.ln(1)

    def key_value_rows(self, rows: List[Tuple[str, str]]):
        label_w, value_w = self._usable_two_col()
        for label, value in rows:
            y = self.get_y()
            self.set_fill_color(248, 249, 251)
            self.rect(self.l_margin, y, label_w, 8, style="F")
            self.rect(self.l_margin + label_w, y, value_w, 8)
            self.set_xy(self.l_margin + 2, y + 1.5)
            self.set_font("Helvetica", "B", 10)
            self.cell(label_w - 4, 5, pdf_safe(label))
            self.set_xy(self.l_margin + label_w + 2, y + 1.5)
            self.set_font("Helvetica", "", 10)
            self.cell(value_w - 4, 5, pdf_safe(value))
            self.ln(8)
        self.ln(2)

    def bullet_lines(self, items: List[str], empty_text: str = "No data found."):
        self.set_font("Helvetica", "", 10)
        if not items:
            self.multi_cell(self._full_width(), 6, pdf_safe(empty_text))
            self.ln(1)
            return
        for item in items:
            self.set_x(self.l_margin + 1)
            self.multi_cell(self._full_width() - 1, 6, pdf_safe(f"- {item}"))
        self.ln(1)

    def note(self, text: str):
        self.set_fill_color(250, 250, 250)
        y = self.get_y()
        self.rect(self.l_margin, y, self._full_width(), 12, style="F")
        self.set_xy(self.l_margin + 3, y + 2)
        self.set_font("Helvetica", "I", 9)
        self.set_text_color(90, 90, 90)
        self.multi_cell(self._full_width() - 6, 4.5, pdf_safe(text))
        self.set_text_color(20, 20, 20)
        self.ln(1)

    def body_text(self, text: str):
        self.set_font("Helvetica", "", 9)
        self.multi_cell(self._full_width(), 4.5, pdf_safe(text))
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
    rows = summary_rows(valid, domain, mx, spf, dmarc, dkim)

    txt_report = out_dir / f"{safe_name(email)}_report.txt"
    pdf_report = out_dir / f"{safe_name(email)}_report.pdf"

    with txt_report.open("w", encoding="utf-8") as f:
        f.write("Email & Domain Technical Report\n")
        f.write(f"Generated: {datetime.now(timezone.utc).isoformat()}\n\n")
        f.write(f"Email: {email}\n")
        f.write(f"Valid format: {'Yes' if valid else 'No'}\n")
        f.write(f"Domain: {domain or 'N/A'}\n\n")
        f.write("Summary\n")
        for label, value in rows:
            f.write(f"- {label}: {value}\n")
        f.write("\nMX Records\n")
        for pref, exch in mx:
            f.write(f"- Priority {pref} - {exch}\n")
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

    pdf.section("Target overview")
    pdf.key_value_rows([
        ("Email address", email),
        ("Domain", domain or "N/A"),
        ("Format validation", "Valid" if valid else "Invalid"),
    ])

    pdf.section("Executive summary", "High-level view of the mail domain posture based on public DNS and WHOIS data.")
    pdf.key_value_rows(rows)

    pdf.section("Mail routing", "MX records show where the domain receives mail.")
    pdf.bullet_lines([f"Priority {pref} - {exch}" for pref, exch in mx], empty_text="No MX records found.")

    pdf.section("Public IP exposure", "A records map the domain to public IPv4 addresses.")
    pdf.bullet_lines(a_records, empty_text="No A records found.")

    pdf.section("Authentication records")
    pdf.key_value_rows([
        ("SPF", "Present" if spf else "Not found"),
        ("DMARC", "Present" if dmarc else "Not found"),
        ("Common DKIM selectors", str(len(dkim))),
    ])

    if spf:
        pdf.note("SPF records discovered")
        pdf.bullet_lines(spf)
    if dmarc:
        pdf.note("DMARC records discovered")
        pdf.bullet_lines(dmarc)

    pdf.section("DKIM quick check", "This only checks a few common selectors and does not prove absence of DKIM.")
    pdf.bullet_lines(dkim, empty_text="No common DKIM selector returned a public TXT record.")

    pdf.section("WHOIS extract", "Trimmed extract of the public WHOIS output for the target domain.")
    pdf.body_text(whois_text[:7000])

    pdf.output(str(pdf_report))

    print(f"TXT report: {txt_report}")
    print(f"PDF report: {pdf_report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
