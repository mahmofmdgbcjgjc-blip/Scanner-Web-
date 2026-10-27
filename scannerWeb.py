
#!/usr/bin/env python3
# Rush Squad Scanner PRO
# For authorized website security auditing only.

import os
import sys
import json
import time
import logging
import argparse
import re

from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin
from http.cookies import SimpleCookie
from dataclasses import dataclass, asdict
from collections import Counter

import requests
import urllib3

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.align import Align
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TaskProgressColumn,
)
from rich.prompt import Prompt, IntPrompt, Confirm
from rich.rule import Rule
from rich import box

urllib3.disable_warnings(
    urllib3.exceptions.InsecureRequestWarning
)

console = Console()
VERSION = "3.0.0"


@dataclass
class Finding:
    category: str
    severity: str
    target: str
    detail: str


class Scanner:
    def __init__(self, target, timeout=10, max_requests=40,
                 exclude=None):
        self.target = self.normalize_url(target)
        self.timeout = max(1, min(timeout, 60))
        self.max_requests = max(1, min(max_requests, 500))
        self.exclude = exclude or []
        self.findings = []
        self.requests_made = 0
        self.started = time.monotonic()

        parsed = urlparse(self.target)
        self.origin = (
            parsed.scheme.lower(),
            (parsed.hostname or "").lower(),
            parsed.port or (443 if parsed.scheme == "https" else 80),
        )

        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": f"RushSquadScanner/{VERSION}",
            "Accept": "text/html,application/xml,text/plain,*/*;q=0.8",
        })

    @staticmethod
    def normalize_url(url):
        url = url.strip()

        if "://" not in url:
            url = "https://" + url

        p = urlparse(url)

        if p.scheme not in ("http", "https") or not p.hostname:
            raise ValueError("Enter a valid HTTP or HTTPS URL.")

        if p.username or p.password:
            raise ValueError("URLs containing credentials are not allowed.")

        try:
            p.port
        except ValueError as exc:
            raise ValueError("Invalid URL port.") from exc

        if p.query or p.fragment:
            raise ValueError("Enter the base URL without query parameters.")

        if any(ch.isspace() for ch in url):
            raise ValueError("URL cannot contain whitespace.")

        return url.rstrip("/")

    def same_origin(self, url):
        p = urlparse(url)
        port = p.port or (443 if p.scheme == "https" else 80)

        return (
            p.scheme.lower(),
            (p.hostname or "").lower(),
            port,
        ) == self.origin

    def excluded(self, url):
        path = urlparse(url).path

        return any(
            path == item.rstrip("/")
            or path.startswith(item.rstrip("/") + "/")
            for item in self.exclude
            if item.strip("/")
        )

    def get(self, url, headers=None):
        if not self.same_origin(url):
            return None

        if self.excluded(url):
            return None

        if self.requests_made >= self.max_requests:
            return None

        self.requests_made += 1

        try:
            return self.session.get(
                url,
                headers=headers or {},
                timeout=self.timeout,
                verify=True,
                allow_redirects=False,
            )
        except requests.RequestException as exc:
            logging.debug("Request failed: %s", exc)
            return None

    def add(self, category, severity, target, detail):
        item = Finding(category, severity, target, detail)

        if item not in self.findings:
            self.findings.append(item)

    def check_robots(self):
        url = urljoin(self.target + "/", "robots.txt")

        if self.excluded(url):
            return

        response = self.get(url)

        if response is None:
            return

        if response.status_code != 200:
            self.add(
                "Robots", "INFO", url,
                f"HTTP status: {response.status_code}"
            )
            return

        rules = re.findall(
            r"(?im)^\s*Disallow:\s*(.*?)\s*$",
            response.text,
        )

        self.add(
            "Robots", "INFO", url,
            f"File accessible; {len(rules)} Disallow rules found."
        )

        for rule in rules[:20]:
            if rule:
                self.add("Robots", "INFO", url, f"Disallow: {rule}")

    def check_sitemap(self):
        url = urljoin(self.target + "/", "sitemap.xml")

        if self.excluded(url):
            return

        response = self.get(url)

        if response is None:
            return

        if response.status_code != 200:
            self.add(
                "Sitemap", "INFO", url,
                f"HTTP status: {response.status_code}"
            )
            return

        locations = re.findall(
            r"<loc>\s*(.*?)\s*</loc>",
            response.text,
            re.IGNORECASE,
        )

        self.add(
            "Sitemap", "INFO", url,
            f"Found {len(locations)} URL entries."
        )

    def check_headers(self):
        response = self.get(self.target)

        if response is None:
            self.add(
                "Connection", "INFO", self.target,
                "Request failed, was excluded, or request limit was reached."
            )
            return

        self.add(
            "HTTP", "INFO", self.target,
            f"Response status: {response.status_code}"
        )

        self.add(
            "HTTP", "INFO", self.target,
            f"Response time: {response.elapsed.total_seconds():.3f}s"
        )

        security_headers = [
            "Content-Security-Policy",
            "X-Content-Type-Options",
            "X-Frame-Options",
            "Referrer-Policy",
            "Permissions-Policy",
        ]

        for header in security_headers:
            if header not in response.headers:
                self.add(
                    "Headers", "LOW", self.target,
                    f"Missing {header}; review based on application needs."
                )

        if (
            urlparse(self.target).scheme == "https"
            and "Strict-Transport-Security" not in response.headers
        ):
            self.add(
                "Headers", "LOW", self.target,
                "HSTS header is missing on HTTPS response."
            )

        server = response.headers.get("Server")
        powered = response.headers.get("X-Powered-By")

        if server:
            self.add(
                "Technology", "INFO", self.target,
                f"Server header: {server}"
            )

        if powered:
            self.add(
                "Technology", "INFO", self.target,
                "X-Powered-By header exposes technology information."
            )

    def check_cookies(self):
        response = self.get(self.target)

        if response is None:
            return

        try:
            headers = response.raw.headers.getlist("Set-Cookie")
        except (AttributeError, TypeError):
            headers = []

        for header in headers:
            cookie = SimpleCookie()

            try:
                cookie.load(header)
            except Exception:
                continue

            for name, morsel in cookie.items():
                missing = []

                if (
                    urlparse(self.target).scheme == "https"
                    and not morsel["secure"]
                ):
                    missing.append("Secure")

                if not morsel["httponly"]:
                    missing.append("HttpOnly")

                if not morsel["samesite"]:
                    missing.append("SameSite")

                if missing:
                    self.add(
                        "Cookies", "LOW", self.target,
                        f"Cookie '{name}' lacks explicit attributes: "
                        f"{', '.join(missing)}. Review its intended use."
                    )

    def check_redirects(self):
        response = self.get(self.target)

        if response is None:
            return

        if response.status_code not in (301, 302, 303, 307, 308):
            return

        location = response.headers.get("Location")

        if not location:
            return

        destination = urljoin(self.target, location)
        dest = urlparse(destination)

        if (
            urlparse(self.target).scheme == "https"
            and dest.scheme == "http"
        ):
            self.add(
                "Redirect", "MEDIUM", self.target,
                "HTTPS endpoint redirects to HTTP; review for downgrade risk."
            )

        if not self.same_origin(destination):
            self.add(
                "Redirect", "INFO", self.target,
                "External redirect detected; this is not proof of a vulnerability."
            )

    def check_cors(self):
        response = self.get(
            self.target,
            headers={"Origin": "https://cors-test.invalid"},
        )

        if response is None:
            return

        origin = response.headers.get(
            "Access-Control-Allow-Origin", ""
        )
        credentials = response.headers.get(
            "Access-Control-Allow-Credentials", ""
        ).lower()

        if origin == "*":
            self.add(
                "CORS", "INFO", self.target,
                "Wildcard origin observed; review resource sensitivity."
            )

            if credentials == "true":
                self.add(
                    "CORS", "INFO", self.target,
                    "Wildcard origin and credentials header coexist. "
                    "Browsers generally reject credentialed responses "
                    "using wildcard origins."
                )

        elif origin == "https://cors-test.invalid":
            self.add(
                "CORS", "INFO", self.target,
                "Test Origin reflected; review origin validation and "
                "credential handling before determining risk."
            )

    def run_check(self, name):
        checks = {
            "Headers": self.check_headers,
            "Cookies": self.check_cookies,
            "CORS": self.check_cors,
            "Redirects": self.check_redirects,
            "Robots.txt": self.check_robots,
            "Sitemap.xml": self.check_sitemap,
        }

        if name not in checks:
            return

        try:
            checks[name]()
        except Exception as exc:
            logging.debug("%s failed: %s", name, exc)
            self.add(
                "Scanner", "INFO", self.target,
                f"{name} check could not complete."
            )

    def full_scan(self, selected=None):
        checks = selected or [
            "Headers", "Cookies", "CORS",
            "Redirects", "Robots.txt", "Sitemap.xml",
        ]

        with Progress(
            SpinnerColumn(style="cyan"),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Scanning...", total=len(checks))

            for name in checks:
                progress.update(task, description=f"Checking {name}")
                self.run_check(name)
                progress.advance(task)
                time.sleep(0.05)

        return self.report()

    def report(self):
        counts = Counter(
            item.severity for item in self.findings
        )

        return {
            "tool": "Rush Squad Scanner PRO",
            "version": VERSION,
            "target": self.target,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "duration_seconds": round(
                time.monotonic() - self.started, 2
            ),
            "requests_made": self.requests_made,
            "total_findings": len(self.findings),
            "severity_counts": dict(counts),
            "findings": [asdict(item) for item in self.findings],
        }


def banner():
    console.clear()

    logo = Text()
    logo.append(
        "██████╗  ██╗   ██╗ ███████╗ ██╗  ██╗\n",
        style="bold bright_cyan",
    )
    logo.append(
        "██╔══██╗ ██║   ██║ ██╔════╝ ██║  ██║\n",
        style="bold bright_cyan",
    )
    logo.append(
        "██████╔╝ ██║   ██║ ███████╗ ███████║\n",
        style="bold cyan",
    )
    logo.append(
        "██╔══██╗ ██║   ██║ ╚════██║ ██╔══██║\n",
        style="bold cyan",
    )
    logo.append(
        "██║  ██║ ╚██████╔╝ ███████║ ██║  ██║\n",
        style="bold bright_blue",
    )
    logo.append(
        "╚═╝  ╚═╝  ╚═════╝  ╚══════╝ ╚═╝  ╚═╝\n",
        style="bold bright_blue",
    )

    console.print(Panel(
        Align.center(logo),
        border_style="bright_cyan",
        box=box.DOUBLE,
        padding=(1, 2),
        title="[bold white]RUSH SQUAD[/]",
        subtitle="[bold bright_magenta]SCANNER PRO v3.0[/]",
    ))

    console.print(Align.center(
        "[dim]WEB SECURITY • CONFIGURATION AUDIT • JSON REPORTS[/]"
    ))
    console.print()


def menu():
    table = Table(
        title="MAIN MENU",
        box=box.ROUNDED,
        border_style="bright_blue",
        expand=True,
    )

    table.add_column("OPTION", style="bold bright_cyan", width=9)
    table.add_column("ACTION", style="white")
    table.add_column("DESCRIPTION", style="dim")

    table.add_row("1", "Full Scan", "Run all checks")
    table.add_row("2", "Security Headers", "Review HTTP headers")
    table.add_row("3", "Cookie Audit", "Review cookie attributes")
    table.add_row("4", "CORS Check", "Inspect CORS response")
    table.add_row("5", "Redirect Check", "Inspect redirect response")
    table.add_row("6", "Robots & Sitemap", "Review public metadata files")
    table.add_row("7", "View Findings", "Show current results")
    table.add_row("8", "Save Report", "Export JSON report")
    table.add_row("9", "Change Target", "Choose another authorized target")
    table.add_row("0", "Exit", "Close the application")

    console.print(table)


def show_findings(scanner):
    table = Table(
        title="SCAN FINDINGS",
        box=box.ROUNDED,
        border_style="cyan",
        expand=True,
    )

    table.add_column("#", style="dim", width=4)
    table.add_column("CATEGORY", style="cyan")
    table.add_column("SEVERITY", width=10)
    table.add_column("DETAIL", overflow="fold")

    colors = {
        "CRITICAL": "bold red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "bright_blue",
        "INFO": "green",
    }

    if not scanner.findings:
        console.print(Panel(
            "[green]No findings recorded yet.[/]",
            title="RESULTS",
            border_style="green",
        ))
        return

    for i, item in enumerate(scanner.findings, 1):
        style = colors.get(item.severity.upper(), "white")
        table.add_row(
            str(i),
            item.category,
            f"[{style}]{item.severity.upper()}[/]",
            item.detail,
        )

    console.print(table)


def save_report(scanner):
    default_name = "rush_report_" + datetime.now().strftime("%Y%m%d_%H%M%S") + ".json"
    path = Prompt.ask("Report filename", default=default_name)

    try:
        with open(path, "w", encoding="utf-8") as file:
            json.dump(
                scanner.report(),
                file,
                indent=2,
                ensure_ascii=False,
            )
        console.print(f"\n[bold green]✓ Report saved:[/] {path}")
    except OSError as exc:
        console.print(f"[bold red]Could not save report:[/] {exc}")


def main():
    parser = argparse.ArgumentParser(
        description="Rush Squad Scanner PRO"
    )
    parser.add_argument("--url", help="Authorized target base URL")
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--max-requests", type=int, default=40)
    parser.add_argument("--report", help="Automatically save JSON report")
    parser.add_argument("--exclude", default="", help="Comma-separated paths")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.ERROR,
        format="[%(levelname)s] %(message)s",
    )

    banner()

    target = args.url

    while not target:
        target = Prompt.ask(
            "[bold cyan]Enter your authorized target URL[/]"
        ).strip()

        try:
            target = Scanner.normalize_url(target)
        except ValueError as exc:
            console.print(f"[red]Invalid URL: {exc}[/]")
            target = None

    try:
        scanner = Scanner(
            target,
            timeout=args.timeout,
            max_requests=args.max_requests,
            exclude=args.exclude.split(","),
        )
    except ValueError as exc:
        console.print(f"[bold red]Error:[/] {exc}")
        return

    while True:
        console.print()
        console.print(Panel(
            f"[bold cyan]Target:[/] {scanner.target}\n"
            f"[bold cyan]Requests:[/] {scanner.requests_made}/"
            f"{scanner.max_requests}    "
            f"[bold cyan]Findings:[/] {len(scanner.findings)}",
            title="CURRENT SESSION",
            border_style="bright_magenta",
        ))

        menu()
        choice = Prompt.ask(
            "\n[bold bright_cyan]Select an option[/]",
            choices=["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"],
            default="1",
        )

        if choice == "0":
            if Confirm.ask("Exit Scanner PRO?", default=True):
                console.print("[bold cyan]Stay safe. Goodbye![/]")
                break

        elif choice == "1":
            scanner.full_scan()

        elif choice == "2":
            scanner.full_scan(["Headers"])

        elif choice == "3":
            scanner.full_scan(["Cookies"])

        elif choice == "4":
            scanner.full_scan(["CORS"])

        elif choice == "5":
            scanner.full_scan(["Redirects"])

        elif choice == "6":
            scanner.full_scan(["Robots.txt", "Sitemap.xml"])

        elif choice == "7":
            show_findings(scanner)

        elif choice == "8":
            save_report(scanner)

        elif choice == "9":
            new_target = Prompt.ask("New authorized target URL")

            try:
                scanner = Scanner(
                    new_target,
                    timeout=args.timeout,
                    max_requests=args.max_requests,
                    exclude=args.exclude.split(","),
                )
                console.print("[green]Target updated.[/]")
            except ValueError as exc:
                console.print(f"[red]Invalid target: {exc}[/]")

        if choice not in ("0", "7", "8", "9"):
            console.print()
            show_findings(scanner)

        if choice != "0":
            Prompt.ask("\n[dim]Press Enter to return to menu[/]", default="")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Scan interrupted by user.[/]")
        sys.exit(130)
