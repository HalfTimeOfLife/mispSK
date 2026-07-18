import argparse

from mispsk.client import MispClient
from mispsk.feeds import (
    resolve_last_sync,
    resolve_recent_volume,
    build_result,
    build_feed_report,
)
from mispsk.dates import get_age


def main():
    parser = argparse.ArgumentParser(
        prog="feed_health.py",
        description="Report last-sync freshness and event volume for each configured MISP feed.",
        epilog="Example: python scripts/feed_health.py --max-age-days 60",
    )
    parser.add_argument(
        "--max-age-days",
        type=int,
        default=30,
        help="Max age (days) since last successful feed sync before flagging as stale (default: 30)",
    )
    args = parser.parse_args()

    client = MispClient()
    misp = client.get_client()

    feeds = misp.feeds(pythonify=True)

    if not feeds:
        print("No feed configured on this MISP instance")
        return

    results = []
    for feed in feeds:
        if not feed.enabled:
            results.append(build_result(feed, status="disabled"))
            continue

        last_sync = resolve_last_sync(feed, misp)
        volume = resolve_recent_volume(feed, misp)

        if last_sync is None:
            status = "unknown"
        else:
            age = get_age(last_sync)
            status = (
                "unknown"
                if age is None
                else ("stale" if age > args.max_age_days else "ok")
            )

        results.append(build_result(feed, last_sync, volume, status))

    build_feed_report(results)


if __name__ == "__main__":
    main()
