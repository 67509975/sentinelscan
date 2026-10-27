import argparse
import json
from datetime import datetime, timezone
from urllib.parse import urlparse
import requests

SECURITY_HEADERS ={
    "Content-Security-Policy":(
        "Helps restrict the sources from which a browser"
        "can load content."
    ),
    "Strict-Transport-Options": (
        "Tells browser to use HTTP for future connections"
    ),
    "X-Content-Type-Options": (
        "Helps prevent browser from incorrectly interpreting"
        "the content type."
    ),
    "X-Frame-Options":(
        "Helps protect against clickjacking."
    ),
    "Refferer-Policy":(
        "Control how much refferer information a browser shares."

    ),
    "Permission-Policy":(
        "Controls access to selected browser features."
    )
}

def validate_url(url):
    """Validate the basic structure of a target URL"""
    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        raise ValueError("URL must begin with http:// or https://.")

    if not  parsed.hostname:
        raise ValueError("URL must contain a hostname.")

    if parsed.username or parsed.password:
        raise ValueError("URL containing credentials are not allowed.")

    return parsed

def scan_website(url):
    """Check an authorised website for basic security issues."""
    parsed = validate_url(url)
    findings = []

    if parsed.scheme != "https":
        findings.append({
            "severity": "HIGH",
            "title": "HTTPS is not being used",
            "details": (
                "The supplied URL uses HTTP, which does not "
                "provide transport encryption."
            ),
            "recommendation": (
                "Configure HTTPS with a valid TLS certificate "
                "and redirect HTTP traffic to HTTPS."
            ),
        })

    try:
        response = requests.get(
            url,
            timeout=10,
            allow_redirects=False,
            verify=True,
            stream=True,
            headers={"User-Agent": "SentinelScan/0.1.0"},
        )

    except requests.RequestException as error:
        raise RuntimeError(
            f"Unable to connect safely to the target: {error}"
        ) from error

    try:
        headers = response.headers

        for header, explanation in SECURITY_HEADERS.items():
            if header not in headers:
                findings.append({
                    "severity": "MEDIUM",
                    "title": f"Missing security header: {header}",
                    "details": explanation,
                    "recommendation": (
                        f"Review whether the {header} header "
                        "should be configured for this application."
                    ),
                })

        if "Server" in headers:
            findings.append({
                "severity": "INFO",
                "title": "Server header is present",
                "details": (
                    f"Server response: {headers['Server']}"
                ),
                "recommendation": (
                    "Review whether revealing server information "
                    "is necessary."
                ),
            })

        return {
            "tool": "SentinelScan",
            "version": "0.1.0",
            "scan_time": datetime.now(timezone.utc).isoformat(),
            "target": url,
            "http_status": response.status_code,
            "findings_count": len(findings),
            "findings": findings,
        }

    finally:
        response.close()


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Identify basic web security misconfigurations "
            "on authorised targets."
        )
    )

    parser.add_argument(
        "url",
        help="URL of a website you own or have permission to scan",
    )

    parser.add_argument(
        "--output",
        default="reports/scan_report.json",
        help="File path for the JSON report",
    )

    args = parser.parse_args()

    try:
        report = scan_website(args.url)

        with open(args.output, "w", encoding="utf-8") as file:
            json.dump(report, file, indent=4)

        print("\nSentinelScan completed.")
        print(f"Target: {report['target']}")
        print(f"HTTP status: {report['http_status']}")
        print(f"Findings: {report['findings_count']}")
        print(f"Report: {args.output}")

        for finding in report["findings"]:
            print(
                f"[{finding['severity']}] "
                f"{finding['title']}"
            )

    except (ValueError, RuntimeError, OSError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
