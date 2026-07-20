import sys
import argparse
import asyncio
import warnings
from webscanner.core.scanner import Scanner
from webscanner.core.plugin_system import PluginRegistry


def create_parser():
    parser = argparse.ArgumentParser(
        prog="webscanner",
        description="WebSec Scanner - Web Vulnerability Scanner & Security Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  webscanner example.com
  webscanner https://example.com -m deep
  webscanner https://example.com -m enterprise -c 30
  webscanner https://example.com -m quick --report json
  webscanner https://example.com -m standard --proxy http://127.0.0.1:8080
  webscanner https://example.com -m deep --rate-limit 5 -H "Authorization: Bearer xxx"
  webscanner --list-plugins
        """,
    )

    parser.add_argument("target", nargs="*", help="Target URL or domain to scan")
    parser.add_argument("-m", "--mode", choices=["quick", "standard", "deep", "enterprise"], default="quick", help="Scan mode (default: quick)")
    parser.add_argument("-c", "--concurrency", type=int, default=0, help="Max concurrent requests (0 = mode default)")
    parser.add_argument("-p", "--proxy", default="", help="Proxy server (e.g., http://127.0.0.1:8080)")
    parser.add_argument("-r", "--report", choices=["html", "json", "csv", "all"], default="html", help="Report format (default: html)")
    parser.add_argument("--crawl-depth", type=int, default=2, help="Crawl depth (default: 2)")
    parser.add_argument("--max-pages", type=int, default=50, help="Max pages to crawl (default: 50)")
    parser.add_argument("--rate-limit", type=float, default=0, help="Max requests per second (0 = unlimited)")
    parser.add_argument("-H", "--header", action="append", default=[], help="Custom HTTP header (can be used multiple times, e.g. -H 'Authorization: Bearer x' -H 'Cookie: session=abc')")
    parser.add_argument("--no-banner", action="store_true", help="Skip banner display")
    parser.add_argument("--list-plugins", action="store_true", help="List all available plugins")

    return parser


def list_plugins():
    PluginRegistry.discover_plugins()
    print("\nAvailable Plugins:")
    print("=" * 60)
    for category in ["recon", "vuln", "cve", "crawl"]:
        plugins = PluginRegistry.list_plugins(category)
        if plugins:
            print(f"\n  [{category.upper()}]")
            for name in plugins:
                plugin_cls = PluginRegistry.get_plugin(name, category)
                desc = getattr(plugin_cls, "description", "") if plugin_cls else ""
                print(f"    - {name}: {desc}")
    print()


async def main():
    parser = create_parser()
    args = parser.parse_args()

    if args.list_plugins:
        PluginRegistry.discover_plugins()
        list_plugins()
        return

    if not args.target:
        parser.print_help()
        sys.exit(1)

    PluginRegistry.discover_plugins()
    target_url = " ".join(args.target)

    custom_headers = {}
    for h in args.header:
        if ":" in h:
            key, val = h.split(":", 1)
            custom_headers[key.strip()] = val.strip()

    scanner = Scanner(
        target=target_url,
        mode=args.mode,
        concurrency=args.concurrency,
        proxy=args.proxy,
        custom_headers=custom_headers,
        rate_limit=args.rate_limit,
    )

    if args.crawl_depth:
        scanner.target.crawl_depth = args.crawl_depth
    if args.max_pages:
        scanner.target.max_pages = args.max_pages

    result = await scanner.run()

    scanner.show_detailed_findings()

    if args.report == "all":
        formats = ["html", "json", "csv"]
    else:
        formats = [args.report]

    report_paths = await scanner.generate_reports(formats)
    for fmt, path in report_paths.items():
        print(f"  [{fmt.upper()}] Report saved: {path}")


if __name__ == "__main__":
    warnings.filterwarnings("ignore", message="I/O operation on closed pipe")
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
    finally:
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                loop.stop()
            if not loop.is_closed():
                loop.close()
        except Exception:
            pass
