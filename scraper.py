import base64
import urllib.parse
import asyncio
from bs4 import BeautifulSoup
import os
import string
import random
import logging
import time
import aiosqlite
import uuid as uuid_
import argparse
import re
import subprocess
import glob
from urllib.parse import urlparse, parse_qs
from curl_cffi import requests
import math
from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.firefox.service import Service as FirefoxService
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.by import By

# Setup logging
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

# Docker-aware paths
WORKDIR = os.environ.get('WORKDIR', '/app/workdir')
DB_FILE = os.path.join(WORKDIR, 'web_archive.db')
TMP_DIR = os.path.join(WORKDIR, '_tmp')
TSV_DIR = os.path.join(WORKDIR, 'tsv_')

# Ensure directories exist
os.makedirs(WORKDIR, exist_ok=True)
os.makedirs(TMP_DIR, exist_ok=True)
os.makedirs(TSV_DIR, exist_ok=True)

# Global WireGuard state
WIREGUARD_CONNECTED = False
WIREGUARD_INTERFACE = None
WIREGUARD_CONFIG_DIR = None
USED_CONFIGS = set()  # Track used config files

# Global IP tracking
IP_ADDRESS_UNVPNED = None
IP_ADDRESS_VPNED = None

# Global sleep configuration
SLEEP_MIN = 1.0
SLEEP_MAX = 10.0

# Global WebDriver state
USE_WEBDRIVER = False
WEBDRIVER_TYPE = None
WEBDRIVER_PATH = None
DRIVER_INSTANCE = None

# ---------------------------
# IP Address Functions
# ---------------------------
def get_current_ip(timeout: int = 10) -> str:
    """Get current public IP address"""
    try:
        time.sleep(2)
        result = subprocess.run(
            ['curl', '-s', 'https://ip.me'],
            # ['curl', '-s', 'https://api.ipify.org'],
            capture_output=True,
            text=True,
            timeout=timeout
        )
        if result.returncode == 0:
            return result.stdout.strip()
        return None
    except Exception as e:
        logging.error(f"Could not fetch IP: {e}")
        return None

def scan_for_new_configs(config_dir: str, used_configs: set) -> list:
    """Scan for new config files not in used_configs"""
    if not os.path.exists(config_dir):
        return []
    
    config_files = glob.glob(os.path.join(config_dir, '*.conf'))
    new_configs = [f for f in config_files if f not in used_configs]
    return new_configs

async def wait_for_new_configs(config_dir: str, used_configs: set, timeout: int = 300) -> str:
    """Wait for new config files to appear, scanning every 30 seconds"""
    start_time = time.time()
    scan_interval = 30
    
    while time.time() - start_time < timeout:
        new_configs = scan_for_new_configs(config_dir, used_configs)
        
        if new_configs:
            selected = random.choice(new_configs)
            logging.info(f"Found new config file: {selected}")
            return selected
        
        logging.info(f"No new configs found. Waiting {scan_interval} seconds...")
        await asyncio.sleep(scan_interval)
    
    logging.error(f"Timeout waiting for new configs after {timeout} seconds")
    return None

# ---------------------------
# WireGuard Connection
# ---------------------------
def disconnect_wireguard():
    """Disconnect WireGuard interface"""
    global WIREGUARD_CONNECTED, WIREGUARD_INTERFACE
    
    if not WIREGUARD_CONNECTED or not WIREGUARD_INTERFACE:
        return
    
    try:
        logging.info(f"Disconnecting WireGuard interface: {WIREGUARD_INTERFACE}")
        subprocess.run(
            ['sudo', 'wg-quick', 'down', WIREGUARD_INTERFACE],
            capture_output=True,
            text=True,
            timeout=30
        )
        WIREGUARD_CONNECTED = False
        WIREGUARD_INTERFACE = None
        logging.info("WireGuard disconnected")
    except Exception as e:
        logging.error(f"Error disconnecting WireGuard: {e}")

async def connect_wireguard(config_dir='wireguard_configs', should_verify_ip=True):
    """Connect to WireGuard with IP verification"""
    global WIREGUARD_CONNECTED, WIREGUARD_INTERFACE, WIREGUARD_CONFIG_DIR
    global IP_ADDRESS_UNVPNED, IP_ADDRESS_VPNED, USED_CONFIGS
    
    WIREGUARD_CONFIG_DIR = config_dir
    
    # Get unVPNed IP if not already stored
    if IP_ADDRESS_UNVPNED is None:
        logging.info("Getting unVPNed IP address...")
        IP_ADDRESS_UNVPNED = get_current_ip()
        if IP_ADDRESS_UNVPNED:
            logging.info(f"UnVPNed IP: {IP_ADDRESS_UNVPNED}")
        else:
            logging.warning("Could not get unVPNed IP address")
    
    # Skip if already connected
    if WIREGUARD_CONNECTED:
        logging.info("WireGuard already connected, skipping connection...")
        return True
    
    if not os.path.exists(config_dir):
        logging.warning(f"WireGuard config directory '{config_dir}' not found. Skipping VPN connection.")
        return False
    
    max_attempts = 10
    attempt = 0
    
    while attempt < max_attempts:
        attempt += 1
        
        # Find available configs (not used yet)
        available_configs = scan_for_new_configs(config_dir, USED_CONFIGS)
        
        if not available_configs:
            logging.warning("No unused configs available. Waiting for new configs...")
            selected_config = await wait_for_new_configs(config_dir, USED_CONFIGS)
            
            if not selected_config:
                logging.error("Failed to find new config files")
                return False
        else:
            selected_config = random.choice(available_configs)
        
        # Mark config as used
        USED_CONFIGS.add(selected_config)
        logging.info(f"Attempt {attempt}/{max_attempts}: Selected WireGuard config: {selected_config}")
        
        try:
            # Bring up WireGuard interface
            result = subprocess.run(
                ['sudo', 'wg-quick', 'up', selected_config],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                WIREGUARD_INTERFACE = os.path.basename(selected_config).replace('.conf', '')
                logging.info(f"WireGuard interface {WIREGUARD_INTERFACE} brought up")
                
                # Wait a moment for connection to stabilize
                await asyncio.sleep(2)
                
                # Get VPNed IP
                IP_ADDRESS_VPNED = get_current_ip()
                
                if IP_ADDRESS_VPNED:
                    logging.info(f"VPNed IP: {IP_ADDRESS_VPNED}")
                    
                    # Verify IP changed if we should verify
                    if should_verify_ip and IP_ADDRESS_UNVPNED:
                        if IP_ADDRESS_VPNED == IP_ADDRESS_UNVPNED:
                            logging.warning(f"IP did not change! Still {IP_ADDRESS_VPNED}")
                            logging.info("Disconnecting and trying another config...")
                            disconnect_wireguard()
                            await asyncio.sleep(2)
                            continue
                        else:
                            logging.info(f"IP successfully changed: {IP_ADDRESS_UNVPNED} -> {IP_ADDRESS_VPNED}")
                            WIREGUARD_CONNECTED = True
                            return True
                    else:
                        # Not verifying IP or no unVPNed IP to compare
                        WIREGUARD_CONNECTED = True
                        return True
                else:
                    logging.warning("Could not verify VPN IP")
                    # Still mark as connected since interface came up
                    WIREGUARD_CONNECTED = True
                    return True
            else:
                logging.error(f"Failed to connect WireGuard: {result.stderr}")
                await asyncio.sleep(2)
                continue
                
        except subprocess.TimeoutExpired:
            logging.error("WireGuard connection timeout")
            await asyncio.sleep(2)
            continue
        except Exception as e:
            logging.error(f"Error connecting to WireGuard: {e}")
            await asyncio.sleep(2)
            continue
    
    logging.error(f"Failed to connect to VPN after {max_attempts} attempts")
    return False

async def random_sleep(min_delay=1.0, max_delay=10.0):
    """Sleep for a random time between min_delay and max_delay seconds."""
    delay = random.uniform(min_delay, max_delay)
    logging.info(f"Sleeping for {delay:.2f} seconds...")
    await asyncio.sleep(delay)
    return delay

async def do_random_sleep():
    """Sleep using global configuration"""
    return await random_sleep(SLEEP_MIN, SLEEP_MAX)

# ---------------------------
# WebDriver Management
# ---------------------------
def init_webdriver(driver_type, driver_path):
    """Initialize WebDriver instance"""
    global DRIVER_INSTANCE
    
    try:
        if driver_type.lower() == 'chrome':
            options = ChromeOptions()
            options.add_argument('--headless')
            options.add_argument('--no-sandbox')
            options.add_argument('--disable-dev-shm-usage')
            options.add_argument('--disable-gpu')
            options.add_argument('--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36')
            
            service = ChromeService(executable_path=driver_path)
            DRIVER_INSTANCE = webdriver.Chrome(service=service, options=options)
            logging.info("Chrome WebDriver initialized")
            
        elif driver_type.lower() == 'firefox':
            options = FirefoxOptions()
            options.add_argument('--headless')
            options.set_preference('general.useragent.override', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:136.0) Gecko/20100101 Firefox/136.0')
            
            service = FirefoxService(executable_path=driver_path)
            DRIVER_INSTANCE = webdriver.Firefox(service=service, options=options)
            logging.info("Firefox WebDriver initialized")
        else:
            logging.error(f"Unsupported driver type: {driver_type}")
            return False
        
        return True
    except Exception as e:
        logging.error(f"Error initializing WebDriver: {e}")
        return False

def cleanup_webdriver():
    """Close and cleanup WebDriver instance"""
    global DRIVER_INSTANCE
    
    if DRIVER_INSTANCE:
        try:
            DRIVER_INSTANCE.quit()
            logging.info("WebDriver closed")
        except Exception as e:
            logging.error(f"Error closing WebDriver: {e}")
        finally:
            DRIVER_INSTANCE = None

# ---------------------------
# Random ID Generator
# ---------------------------
def WARCH_generate_random_id(length: int = 15) -> str:
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(length))

# ---------------------------
# Create Table if not exists
# ---------------------------
async def WARCH_create_table():
    async with aiosqlite.connect(DB_FILE) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS web_page_archive (
                UUID TEXT PRIMARY KEY,
                SOURCE_URL TEXT NOT NULL,
                FRIENDLY_ID TEXT,
                TIMESTAMP INTEGER NOT NULL,
                SIZE INTEGER,
                LAST_MOD INTEGER
            )
        """)
        await db.commit()
        logging.info("Database table ensured.")

# ---------------------------
# Save record to database
# ---------------------------
async def WARCH_save_to_db(uuid: str, url: str, friendly_id: str, timestamp: int, size: int, last_mod: int):
    async with aiosqlite.connect(DB_FILE) as db:
        await db.execute("""
            INSERT INTO web_page_archive (UUID, SOURCE_URL, FRIENDLY_ID, TIMESTAMP, SIZE, LAST_MOD)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (uuid, url, friendly_id, timestamp, size, last_mod))
        await db.commit()
        logging.info(f"Inserted {uuid} into database.")

# ---------------------------
# Fetch URL with WebDriver
# ---------------------------
async def WARCH_fetch_webdriver(url: str, friendly_id: str = None, max_retries: int = -1) -> str:
    """Fetch URL using WebDriver"""
    if friendly_id is None:
        friendly_id = WARCH_generate_random_id()
    
    random_id = str(uuid_.uuid4())
    tmp_path = os.path.join(TMP_DIR, friendly_id)
    
    retry_count = 0
    
    while max_retries == -1 or retry_count <= max_retries:
        try:
            DRIVER_INSTANCE.get(url)
            
            # Wait for page to load (adjust as needed)
            WebDriverWait(DRIVER_INSTANCE, 10).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )
            
            # Get page source
            content = DRIVER_INSTANCE.page_source.encode('utf-8')
            
            with open(tmp_path, 'wb') as f:
                f.write(content)
            logging.info(f"Saved {url} to {tmp_path} [{len(content)} bytes] via WebDriver")

            timestamp = int(time.time())
            last_mod = timestamp

            await WARCH_save_to_db(
                uuid=random_id,
                url=url,
                friendly_id=friendly_id,
                timestamp=timestamp,
                size=len(content),
                last_mod=last_mod
            )

            return friendly_id
                
        except Exception as e:
            retry_count += 1
            retry_info = f"(retry {retry_count}" + (")" if max_retries == -1 else f"/{max_retries})")
            logging.error(f"Exception during WebDriver fetch {retry_info}: {e}")
            
            if max_retries != -1 and retry_count > max_retries:
                logging.error(f"Max retries ({max_retries}) exceeded. Giving up.")
                return None
            
            await do_random_sleep()
            continue

# ---------------------------
# Fetch URL and save to tmp + DB (requests version with retry)
# ---------------------------
async def WARCH_fetch_and_save(url: str, method: str = 'GET', headers: dict = None, 
                                data: dict = None, friendly_id: str = None, session=None,
                                max_retries: int = -1) -> str:
    # Use WebDriver if enabled
    if USE_WEBDRIVER:
        return await WARCH_fetch_webdriver(url, friendly_id, max_retries)
    
    if friendly_id is None:
        friendly_id = WARCH_generate_random_id()
    
    random_id = str(uuid_.uuid4())
    tmp_path = os.path.join(TMP_DIR, friendly_id)
    
    retry_count = 0
    
    while max_retries == -1 or retry_count <= max_retries:
        try:
            response = session.request(method, url, headers=headers, data=data)
            
            if response.status_code == 200:
                with open(tmp_path, 'wb') as f:
                    f.write(response.content)
                logging.info(f"Saved {url} to {tmp_path} [{len(response.content)} bytes]")

                # Get timestamp and last-modified
                timestamp = int(time.time())
                last_mod_header = response.headers.get('Last-Modified')
                if last_mod_header:
                    try:
                        last_mod = int(time.mktime(time.strptime(last_mod_header, '%a, %d %b %Y %H:%M:%S %Z')))
                    except Exception:
                        last_mod = timestamp
                else:
                    last_mod = timestamp

                # Save metadata async
                await WARCH_save_to_db(
                    uuid=random_id,
                    url=url,
                    friendly_id=friendly_id,
                    timestamp=timestamp,
                    size=len(response.content),
                    last_mod=last_mod
                )

                return friendly_id
            else:
                # Print page content to console if non-200
                logging.error(f"Non-200 status code: {response.status_code}")
                print(f"\n{'='*80}")
                print(f"NON-200 RESPONSE FOR: {url}")
                print(f"STATUS CODE: {response.status_code}")
                print(f"{'='*80}")
                print(response.text[:5000])  # Print first 5000 chars
                print(f"{'='*80}\n")
                raise Exception(f"Non-200 status code: {response.status_code}")
                
        except Exception as e:
            retry_count += 1
            retry_info = f"(retry {retry_count}" + (")" if max_retries == -1 else f"/{max_retries})")
            logging.error(f"Exception during fetch {retry_info}: {e}")
            
            if max_retries != -1 and retry_count > max_retries:
                logging.error(f"Max retries ({max_retries}) exceeded. Giving up.")
                return None
            
            await do_random_sleep()
            continue

async def WARCH_get_content_by_uuid(uuid_input: str) -> str:
    tmp_path = os.path.join(TMP_DIR, uuid_input)
    if os.path.exists(tmp_path):
        with open(tmp_path, 'r', encoding='utf-8') as f:
            return f.read()
    else:
        logging.error(f"UUID {uuid_input} not found in tmp.")
        return None

# ---------------------------
# DPWH Table Parser
# ---------------------------
def dpwh_table_to_tsv(html: str) -> str:
    """Convert DPWH HTML table to TSV format"""
    soup = BeautifulSoup(html, "lxml")

    table = soup.find("table")
    if not table:
        return ""

    # Extract header names
    headers = []
    for th in table.find_all("th"):
        col_name = th.get_text(strip=True)
        headers.append(col_name)

    rows_data = []

    for tr in table.find_all("tr"):
        tds = tr.find_all("td")
        if not tds:
            continue

        row_dict = {}
        for idx, td in enumerate(tds):
            col_name = headers[idx] if idx < len(headers) else f"col{idx+1}"
            a_tag = td.find("a", href=True)

            if a_tag:
                # Split into href and name columns
                row_dict[f"{col_name}_href"] = a_tag["href"].strip()
                row_dict[f"{col_name}_name"] = a_tag.get_text(strip=True)
            else:
                # Plain text cell
                row_dict[col_name] = td.get_text(strip=True)

        rows_data.append(row_dict)

    # Collect all possible columns (since <a> splits add new ones)
    all_columns = []
    for row in rows_data:
        for key in row.keys():
            if key not in all_columns:
                all_columns.append(key)

    # Build TSV output
    lines = ["\t".join(all_columns)]
    for row in rows_data:
        line = "\t".join(row.get(col, "") for col in all_columns)
        lines.append(line)

    return "\n".join(lines)

# ---------------------------
# DPWH Pagination Parser
# ---------------------------
def get_last_page_query_string(html: str) -> int:
    """Extract last page number from query string in pagination HTML"""
    try:
        soup = BeautifulSoup(html, "html.parser")
        # Get the last <li> that contains an <a> within .item-list .pager
        li_tags = soup.select(".item-list ul.pager li a[href]")
        if not li_tags:
            return None

        href = li_tags[-1].get("href", "")
        if not href:
            return None

        query = urllib.parse.urlparse(href).query
        params = urllib.parse.parse_qs(query)
        page = params.get("page", [None])[0]

        return int(page) if page and str(page).isdigit() else None
    except Exception as e:
        logging.error(f"Error extracting page from query string: {e}")
        return None

async def get_last_page_with_retry(initial_url: str, initial_prefix: str, session, headers: dict, max_retries: int = -1) -> int:
    """Get last page number with improved retry logic"""
    current_url = initial_url
    retry_count = 0
    temp_last_page_list = []  # Store all detected page numbers
    
    while max_retries == -1 or retry_count <= max_retries:
        logging.info(f"LPQS: {retry_count}/{max_retries}")

        retry_count += 1
        # Fetch current URL
        friendly_id = await WARCH_fetch_and_save(current_url, session=session, headers=headers, max_retries=max_retries)
        
        if not friendly_id:
            retry_info = f"(retry {retry_count}" + (")" if max_retries == -1 else f"/{max_retries})")
            logging.error(f"Failed to fetch page for last page detection {retry_info}")
            
            if max_retries != -1 and retry_count > max_retries:
                logging.error(f"Max retries ({max_retries}) exceeded for last page detection.")
                # Return largest page number found, or 0 if none found
                if temp_last_page_list:
                    largest_page = max(temp_last_page_list)
                    logging.info(f"Returning largest detected page number: {largest_page}")
                    return largest_page
                else:
                    logging.error("No page numbers detected. Giving up.")
                    return 0
            
            await do_random_sleep()
            continue
        
        current_url_html = await WARCH_get_content_by_uuid(friendly_id)
        
        # Get temp_last_page from current URL
        temp_last_page = get_last_page_query_string(current_url_html)
        
        if temp_last_page is None:
            retry_count += 1
            retry_info = f"(retry {retry_count}" + (")" if max_retries == -1 else f"/{max_retries})")
            logging.error(f"Cannot detect last page number from current URL {retry_info}")
            
            if max_retries != -1 and retry_count > max_retries:
                logging.error(f"Max retries ({max_retries}) exceeded for last page detection.")
                # Return largest page number found, or 0 if none found
                if temp_last_page_list:
                    largest_page = max(temp_last_page_list)
                    logging.info(f"Returning largest detected page number: {largest_page}")
                    return largest_page
                else:
                    logging.error("No page numbers detected. Giving up.")
                    return 0
            
            await do_random_sleep()
            continue
        
        # Store detected page number
        temp_last_page_list.append(temp_last_page)
        logging.info(f"Detected page number: {temp_last_page} (stored in list)")
        
        # Construct URL for temp_last_page
        temp_last_page_url = dpwh_modify_page_param(input_urlprefix=initial_prefix, input_pagenum=temp_last_page)
        
        # Fetch temp_last_page URL
        temp_friendly_id = await WARCH_fetch_and_save(temp_last_page_url, session=session, headers=headers, max_retries=max_retries)
        
        if not temp_friendly_id:
            retry_count += 1
            retry_info = f"(retry {retry_count}" + (")" if max_retries == -1 else f"/{max_retries})")
            logging.error(f"Failed to fetch temp_last_page URL {retry_info}")
            
            if max_retries != -1 and retry_count > max_retries:
                logging.error(f"Max retries ({max_retries}) exceeded for last page detection.")
                # Return largest page number found
                if temp_last_page_list:
                    largest_page = max(temp_last_page_list)
                    logging.info(f"Returning largest detected page number: {largest_page}")
                    return largest_page
                else:
                    logging.error("No page numbers detected. Giving up.")
                    return 0
            
            await do_random_sleep()
            continue
        
        temp_last_page_html = await WARCH_get_content_by_uuid(temp_friendly_id)
        
        # Get new_last_page from temp_last_page URL
        new_last_page = get_last_page_query_string(temp_last_page_html)
        
        if new_last_page is None:
            retry_count += 1
            retry_info = f"(retry {retry_count}" + (")" if max_retries == -1 else f"/{max_retries})")
            logging.error(f"Cannot detect last page number from temp_last_page URL {retry_info}")
            
            if max_retries != -1 and retry_count > max_retries:
                logging.error(f"Max retries ({max_retries}) exceeded for last page detection.")
                # Return largest page number found
                if temp_last_page_list:
                    largest_page = max(temp_last_page_list)
                    logging.info(f"Returning largest detected page number: {largest_page}")
                    return largest_page
                else:
                    logging.error("No page numbers detected. Giving up.")
                    return 0
            
            await do_random_sleep()
            continue
        
        # Store this page number too
        temp_last_page_list.append(new_last_page)
        logging.info(f"Detected page number: {new_last_page} (stored in list)")
        
        # Check if they match
        if new_last_page != temp_last_page:
            logging.info(f"Page numbers don't match (temp={temp_last_page}, new={new_last_page}). Continuing search...")
            current_url = temp_last_page_url
            # Don't increment retry_count here since this is expected behavior
            await do_random_sleep()
            continue
        else:
            # They match - we found the final page
            logging.info(f"Found final page: {new_last_page}")
            return new_last_page
    
    # If we exit the loop without returning, return largest found page
    if temp_last_page_list:
        largest_page = max(temp_last_page_list)
        logging.info(f"Returning largest detected page number: {largest_page}")
        return largest_page
    
    return 0

# ---------------------------
# DPWH URL Manipulation
# ---------------------------
def dpwh_modify_page_param(input_urlprefix: str, input_pagenum) -> str:
    """Modify or add the 'page' query parameter in a URL"""
    parsed = urllib.parse.urlparse(input_urlprefix)
    query_params = urllib.parse.parse_qs(parsed.query)
    
    # Update 'page' parameter
    query_params['page'] = [str(input_pagenum)]
    
    # Rebuild the query string
    new_query = urllib.parse.urlencode(query_params, doseq=True)
    
    # Return the reconstructed URL
    return urllib.parse.urlunparse(parsed._replace(query=new_query))

def gen_dpwh_new_url_prefix(prefix: str, html: str) -> str:
    """Generate DPWH query URL from form HTML"""
    soup = BeautifulSoup(html, "html.parser")
    params = {}

    # find all select and input elements whose id starts with "edit-data"
    for tag in soup.find_all(['select', 'input']):
        tid = tag.get('id', '')
        if tid.startswith('edit-data'):
            # normalize id: remove "edit-" and replace "-" with "_"
            param_name = tid.replace('edit-', '').replace('-', '_')
            # assign default value based on tag type
            if tag.name == 'select':
                params[param_name] = 'All'
            elif tag.name == 'input':
                params[param_name] = ''
    
    query = urllib.parse.urlencode(params)
    return f"{prefix}?{query}"

def strip_query_string(url):
    """Removes the query string from a URL"""
    parsed_url = urllib.parse.urlparse(url)
    # Rebuild the URL without the query
    stripped_url = urllib.parse.urlunparse(parsed_url._replace(query=""))
    return stripped_url

# ---------------------------
# Page String Parser
# ---------------------------
def parse_page_string(page_string: str, min_page: int, max_page: int) -> list:
    """
    Parse page string with comma and hyphen ranges.
    Returns sorted list of page numbers or None if error.
    
    Examples:
        "1,59,32" -> [1, 32, 59]
        "29-68" -> [29, 30, ..., 68]
        "38-71,90-133,209" -> [38, ..., 71, 90, ..., 133, 209]
    """
    if not page_string or not page_string.strip():
        return None
    
    pages = set()
    parts = page_string.split(',')
    
    try:
        for part in parts:
            part = part.strip()
            
            if '-' in part:
                # Handle range
                range_parts = part.split('-')
                if len(range_parts) != 2:
                    logging.error(f"Invalid range format: {part}")
                    return None
                
                start = int(range_parts[0])
                end = int(range_parts[1])
                
                # Check if first value is larger than second
                if start > end:
                    logging.error(f"Invalid range: first value ({start}) is larger than second value ({end})")
                    return None
                
                # Check if out of bounds
                if start < min_page or end > max_page:
                    logging.error(f"Range {start}-{end} is out of bounds (valid range: {min_page}-{max_page})")
                    return None
                
                pages.update(range(start, end + 1))
            else:
                # Handle single number
                num = int(part)
                
                # Check if out of bounds
                if num < min_page or num > max_page:
                    logging.error(f"Page number {num} is out of bounds (valid range: {min_page}-{max_page})")
                    return None
                
                pages.add(num)
        
        return sorted(list(pages))
    
    except ValueError as e:
        logging.error(f"Error parsing page string: {e}")
        return None

# ---------------------------
# Table Extraction with Retry
# ---------------------------
async def extract_table_with_retry(url: str, session, headers: dict, friendly_id: str, 
                                   max_retries: int = -1) -> tuple:
    """Extract table with retry logic. Returns (success, tsv_content)"""
    retry_count = 0
    
    while max_retries == -1 or retry_count <= max_retries:
        curpage_url_uuid = await WARCH_fetch_and_save(
            url,
            session=session,
            headers=headers,
            friendly_id=friendly_id,
            max_retries=max_retries
        )
        
        if not curpage_url_uuid:
            retry_count += 1
            retry_info = f"(retry {retry_count}" + (")" if max_retries == -1 else f"/{max_retries})")
            logging.error(f"Failed to fetch page {retry_info}")
            
            if max_retries != -1 and retry_count > max_retries:
                logging.error(f"Max retries ({max_retries}) exceeded for table extraction. Giving up.")
                return False, ""
            
            await do_random_sleep()
            continue
        
        curpage_url_text = await WARCH_get_content_by_uuid(curpage_url_uuid)
        tsv_content = dpwh_table_to_tsv(curpage_url_text)
        
        if tsv_content:
            return True, tsv_content
        
        retry_count += 1
        retry_info = f"(retry {retry_count}" + (")" if max_retries == -1 else f"/{max_retries})")
        logging.error(f"Cannot detect table in HTML {retry_info}")
        
        if max_retries != -1 and retry_count > max_retries:
            logging.error(f"Max retries ({max_retries}) exceeded for table extraction. Giving up.")
            return False, ""
        
        await do_random_sleep()
    
    return False, ""

def dpwh_get_basename(url: str) -> str:
    parsed = urlparse(url)
    # Remove domain, keep only path
    path = parsed.path.strip('/')
    # Replace slashes with dashes
    basename = path.replace('/', '-')
    # Combine netloc (domain) and path with a dash
    result = f"{parsed.netloc.replace('.', '-')}-{basename}" if basename else parsed.netloc.replace('.', '-')
    return result

async def main():
    global SLEEP_MIN, SLEEP_MAX, USE_WEBDRIVER, WEBDRIVER_TYPE, WEBDRIVER_PATH
    
    parser = argparse.ArgumentParser(description="DPWH TSV parser with WireGuard and WebDriver support")
    parser.add_argument('--input-url', type=str, required=True, help='URL to be used as input')
    parser.add_argument('--start-num', type=int, default=None, help='Starting number (default: 0 if --page-string not used)')
    parser.add_argument('--end-num', type=int, default=None, help='Ending number (must not exceed last_page_num)')
    parser.add_argument('--page-string', type=str, default=None, 
                        help='Page ranges (e.g., "1,59,32" or "29-68" or "38-71,90-133,209")')
    parser.add_argument('--wireguard-dir', type=str, default='/app/wireguard_configs', 
                        help='Directory containing WireGuard .conf files')
    parser.add_argument('--no-vpn', action='store_true', help='Skip WireGuard connection')
    parser.add_argument('--max-lastpage-retry', type=int, default=10, 
                        help='Max retries for last page detection (-1 for infinite, default: 10)')
    parser.add_argument('--max-table-retry', type=int, default=-1, 
                        help='Max retries for table extraction (-1 for infinite, default: -1)')
    parser.add_argument('--min-sleep-time', type=float, default=1.0,
                        help='Minimum sleep time in seconds (default: 1.0)')
    parser.add_argument('--max-sleep-time', type=float, default=10.0,
                        help='Maximum sleep time in seconds (default: 10.0)')
    parser.add_argument('--chromedriver-path', type=str, default=None,
                        help='Path to ChromeDriver executable')
    parser.add_argument('--webdriver-type', type=str, choices=['chrome', 'firefox'], default=None,
                        help='WebDriver type (chrome or firefox)')
    parser.add_argument('--force-requests', action='store_true',
                        help='Force use of requests even if WebDriver args are present')
    args = parser.parse_args()
    
    # Set global sleep configuration
    SLEEP_MIN = args.min_sleep_time
    SLEEP_MAX = args.max_sleep_time
    logging.info(f"Sleep time configured: {SLEEP_MIN}s - {SLEEP_MAX}s")
    
    # Determine if WebDriver should be used
    if not args.force_requests and args.webdriver_type and args.chromedriver_path:
        USE_WEBDRIVER = True
        WEBDRIVER_TYPE = args.webdriver_type
        WEBDRIVER_PATH = args.chromedriver_path
        
        if not init_webdriver(WEBDRIVER_TYPE, WEBDRIVER_PATH):
            logging.error("Failed to initialize WebDriver. Exiting.")
            return
    else:
        if args.force_requests:
            logging.info("Forcing requests usage")
        logging.info("Using requests for HTTP requests")
    
    initial_url = strip_query_string(args.input_url)
    
    # Connect to WireGuard ONCE with IP verification
    if not args.no_vpn:
        success = await connect_wireguard(args.wireguard_dir, should_verify_ip=True)
        if not success:
            logging.error("Failed to establish VPN connection. Exiting.")
            cleanup_webdriver()
            return
    
    # Create requests session
    s = requests.Session() if not USE_WEBDRIVER else None
    http_headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:136.0) Gecko/20100101 Firefox/136.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
        'Sec-Fetch-User': '?1',
        'Sec-GPC': '1',
        'Priority': 'u=0, i',
        'Pragma': 'no-cache',
        'Cache-Control': 'no-cache',
    }
    
    try:
        initial_url_uuid = await WARCH_fetch_and_save(
            initial_url, 
            session=s, 
            headers=http_headers,
            max_retries=args.max_lastpage_retry
        )
        print(initial_url_uuid)
        
        if initial_url_uuid:
            initial_url_text = await WARCH_get_content_by_uuid(initial_url_uuid)
            logging.info(f"Fetched HTML content length: {len(initial_url_text)}")
            
            initial_prefix = gen_dpwh_new_url_prefix(prefix=initial_url, html=initial_url_text)
            
            # Get last page with new retry logic
            last_page_num = await get_last_page_with_retry(
                initial_url, 
                initial_prefix,
                s,
                http_headers,
                max_retries=args.max_lastpage_retry
            )
            
            if last_page_num == 0:
                logging.error("Could not determine last page number. Exiting.")
                return
            
            logging.info(f'Last page number: {last_page_num}')
            
            # Determine page range to scrape
            pages_to_scrape = None
            
            if args.page_string:
                # Use --page-string if provided
                logging.info(f"Using --page-string: {args.page_string}")
                pages_to_scrape = parse_page_string(args.page_string, 0, last_page_num)
                
                if pages_to_scrape is None:
                    logging.error("Failed to parse --page-string. Exiting.")
                    return
                
                logging.info(f"Pages to scrape: {len(pages_to_scrape)} pages")
            else:
                # Use --start-num and --end-num
                start_num = 0 if args.start_num is None else args.start_num
                end_num = last_page_num if args.end_num is None else args.end_num
                
                # Validate range
                if start_num < 0:
                    logging.error(f"--start-num ({start_num}) cannot be negative. Exiting.")
                    return
                
                if end_num > last_page_num:
                    logging.warning(f"--end-num ({end_num}) exceeds last_page_num ({last_page_num}). Using {last_page_num} instead.")
                    end_num = last_page_num
                
                if end_num < start_num:
                    logging.error(f"--end-num ({end_num}) is less than --start-num ({start_num}). Exiting.")
                    return
                
                pages_to_scrape = list(range(start_num, end_num + 1))
                logging.info(f"Pages to scrape: {start_num} to {end_num}")
            
            short_basename = dpwh_get_basename(initial_url)
            total_pages = len(pages_to_scrape)
            
            for idx, curpage_num in enumerate(pages_to_scrape, 1):
                logging.info(f"PAGE {short_basename} {curpage_num} ({idx}/{total_pages})")
                curpage_url = dpwh_modify_page_param(input_urlprefix=initial_prefix, input_pagenum=curpage_num)
                curpage_localfilename = short_basename + "_" + f"{curpage_num:09d}"
                
                # Extract table with retry
                success, tsv_content = await extract_table_with_retry(
                    curpage_url,
                    s,
                    http_headers,
                    curpage_localfilename + ".html",
                    max_retries=args.max_table_retry
                )
                
                if success:
                    os.makedirs(TSV_DIR, exist_ok=True)
                    
                    with open(os.path.join(TSV_DIR, (curpage_localfilename + ".tsv")), "w") as f:
                        f.write(tsv_content)
                else:
                    logging.error(f"Failed to extract table for page {curpage_num}")
                
                # Sleep between requests (except after the last page)
                if idx < total_pages:
                    await do_random_sleep()
            
            print(f"Completed scraping {total_pages} pages")
            logging.info(f"Final IP address: {get_current_ip()}")
    
    finally:
        cleanup_webdriver()
        disconnect_wireguard()

if __name__ == "__main__":
    try:
        asyncio.run(WARCH_create_table())
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("Interrupted by user")
        cleanup_webdriver()
        disconnect_wireguard()
