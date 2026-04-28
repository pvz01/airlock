# Airlock Documentation Exporter
#
# This script does not use the Airlock Digital REST API. Instead, it demonstrates
# how to scrape the web UI to extract a snapshot of the built-in documentation
# and export it to a single PDF. While printing an individual page to PDF is
# trivial, this script is intended for bulk export. As of writing, the documentation
# consists of ~90 articles.
#
# The script logs into an Airlock server, retrieves the running server version
# from the Dashboard (Server Health), and exports the built-in documentation into
# a single merged PDF file. It uses Playwright to automate a headless Chromium
# browser for authentication, navigation, expanding the documentation sidebar,
# and rendering each page to PDF. BeautifulSoup is used to parse the rendered
# HTML and collect all documentation links, including nested pages. PyPDF is
# then used to merge the individual page PDFs into one final document.
#
# The output file is named using the server FQDN, Airlock version, and a UTC
# timestamp, producing a portable snapshot of the live documentation. Temporary
# PDF files are generated during processing and automatically cleaned up after
# the final document is created.
#
# Core dependencies:
# - playwright (browser automation and PDF rendering)
# - beautifulsoup4 (HTML parsing)
# - pypdf (PDF merging)
#
# Installation:
#   pip install playwright beautifulsoup4 pypdf
#   python -m playwright install chromium
#
# Usage:
#   python export_airlock_docs.py
#
# You will be prompted for:
# - Server FQDN
# - Username
# - Password
#
# Notes:
# - Assumes Airlock docs are available at /docs/
# - Assumes standard web UI login (non-SSO, no MFA)
# - Designed for simplicity and readability, not full resiliency

from getpass import getpass
from urllib.parse import urljoin, urlparse
from datetime import datetime, timezone
import time
import os

from playwright.sync_api import sync_playwright
from bs4 import BeautifulSoup
from pypdf import PdfWriter

DOCS_ROOT = "/docs/"


def normalize_base_url(user_input):
    user_input = user_input.strip()

    if not user_input.startswith("http"):
        user_input = "https://" + user_input

    parsed = urlparse(user_input)

    scheme = parsed.scheme or "https"
    hostname = parsed.hostname
    port = parsed.port if parsed.port else 3128

    return f"{scheme}://{hostname}:{port}"


def get_server_version(page, base_url):
    print("\n[2/5] Retrieving server version...")

    page.goto(urljoin(base_url, "/dashboard"), wait_until="networkidle")

    page.locator("text=Server Health").first.click()
    page.wait_for_timeout(1500)

    html = page.content()
    soup = BeautifulSoup(html, "html.parser")

    version_text = None

    for row in soup.find_all(string=lambda t: t and "Current Version" in t):
        parent = row.parent
        if parent:
            container = parent.find_parent()
            if container:
                version_text = container.get_text(strip=True)
                break

    if not version_text:
        print("[2/5] WARNING: Could not find version, defaulting to unknown")
        return "unknown"

    import re
    match = re.search(r"\d+\.\d+\.\d+\.\d+", version_text)

    if match:
        version = match.group(0)
        print(f"[2/5] Found version: {version}")
        return version

    print("[2/5] WARNING: Could not parse version, defaulting to unknown")
    return "unknown"


def build_output_filename(base_url, version):
    parsed = urlparse(base_url)
    host = parsed.hostname

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H%M")

    return f"airlock_doc_export_{host}_{version}_{timestamp}.pdf"


def login(page, base_url, username, password):
    print("\n[1/5] Logging in...")

    page.goto(base_url, wait_until="networkidle")

    page.fill('input[type="text"]', username)
    page.fill('input[type="password"]', password)

    page.click('button[type="submit"], input[type="submit"]')
    page.wait_for_load_state("networkidle")

    print("[1/5] Login complete")


def get_doc_links(page, base_url):
    print("\n[3/5] Discovering documentation pages...")

    page.goto(urljoin(base_url, DOCS_ROOT), wait_until="networkidle")

    print("[3/5] Expanding navigation tree...")

    for _ in range(5):
        buttons = page.locator(
            'button[aria-expanded="false"], '
            '.menu__caret, '
            '.menu__link--sublist'
        )

        count = buttons.count()

        for i in range(count):
            try:
                buttons.nth(i).click(timeout=1000)
                page.wait_for_timeout(200)
            except Exception:
                pass

    print("[3/5] Collecting links...")

    soup = BeautifulSoup(page.content(), "html.parser")

    links = []

    for a in soup.select("a[href]"):
        href = a["href"]

        if href.startswith("#"):
            continue

        parsed_href = urlparse(href)

        if parsed_href.netloc and parsed_href.netloc != urlparse(base_url).netloc:
            continue

        clean_path = parsed_href.path.split("#")[0]

        if not clean_path.startswith(DOCS_ROOT):
            continue

        full = urljoin(base_url, clean_path)

        if full not in links:
            links.append(full)

    print(f"[3/5] Found {len(links)} pages")
    return links


def render_pdfs(page, links):
    print("\n[4/5] Rendering PDFs...")

    pdf_files = []
    start_time = time.time()

    for i, url in enumerate(links, start=1):
        page_start = time.time()

        print(f"[4/5] ({i}/{len(links)}) Rendering: {url}")

        page.goto(url, wait_until="networkidle")

        filename = f"temp_{i}.pdf"

        page.pdf(
            path=filename,
            format="A4",
            print_background=True,
        )

        pdf_files.append(filename)

        elapsed = round(time.time() - page_start, 1)
        print(f"[4/5] ({i}/{len(links)}) Done in {elapsed}s")

    total_elapsed = round(time.time() - start_time, 1)
    print(f"[4/5] Completed in {total_elapsed}s")

    return pdf_files


def merge_pdfs(files, output_file):
    print("\n[5/5] Merging PDFs...")

    writer = PdfWriter()

    for i, f in enumerate(files, start=1):
        print(f"[5/5] Adding {i}/{len(files)}: {f}")
        writer.append(f)

    with open(output_file, "wb") as out:
        writer.write(out)

    print("[5/5] Merge complete")


def cleanup_temp_files(files):
    print("[5/5] Cleaning up temporary files...")

    for f in files:
        try:
            os.remove(f)
        except Exception:
            pass

    print("[5/5] Cleanup complete")


def main():
    print("=== Airlock Docs Export ===")

    server = input("Server: ")
    base_url = normalize_base_url(server)

    print(f"Using: {base_url}")

    username = input("Username: ")
    password = getpass("Password: ")

    overall_start = time.time()

    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(ignore_https_errors=True)

        login(page, base_url, username, password)

        version = get_server_version(page, base_url)

        output_file = build_output_filename(base_url, version)
        print(f"Output file: {output_file}")

        links = get_doc_links(page, base_url)

        pdfs = render_pdfs(page, links)

        merge_pdfs(pdfs, output_file)

        cleanup_temp_files(pdfs)

        browser.close()

    total_time = round(time.time() - overall_start, 1)

    print(f"\nDone: {output_file}")
    print(f"Total time: {total_time}s")


if __name__ == "__main__":
    main()