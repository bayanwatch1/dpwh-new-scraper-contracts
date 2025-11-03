import asyncio
import subprocess

INPUT_FILE = "input.dpwh.new.urls.v2.txt"

SERVICE_NAME = "dpwh_new_scraper2"
CHROMEDRIVER_PATH = "/usr/local/bin/chromedriver"

async def clean_containers():
    # Remove existing containers from the same service
    await asyncio.create_subprocess_shell(
        f"docker compose ps -q {SERVICE_NAME} | xargs -r docker rm -f",
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL
    )

async def prune_containers():
    await asyncio.create_subprocess_shell(
        "docker container prune -f",
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL
    )

async def run_scraper(url):
    cmd = (
        f"docker compose run --rm -T {SERVICE_NAME} "
        f"python3 scraper.py "
        f"--input-url '{url}' "
        f"--webdriver-type chrome "
        f"--chromedriver-path {CHROMEDRIVER_PATH}"
    )
    proc = await asyncio.create_subprocess_shell(cmd)
    await proc.wait()

async def main():
    await clean_containers()

    async with asyncio.Semaphore(1):  # sequential; raise for concurrency
        with open(INPUT_FILE, "r") as f:
            for line in f:
                url = line.strip()
                if not url:
                    continue
                await run_scraper(url)
                await prune_containers()

if __name__ == "__main__":
    asyncio.run(main())
