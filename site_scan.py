#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Crawls a website, sticking to just the given domain and not following external links. Reports non-200 response codes
to the emails provided if any. Emails can be omitted if you're just interested in warming the cache.

by Phillip Stromberg
on 2015-01-27
"""

import boto3
from bs4 import BeautifulSoup, SoupStrainer, FeatureNotFound
import logging as _logging
from multiprocessing import cpu_count
from multiprocessing.dummy import Pool
import os
import requests
from requests import adapters

try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO
import sys
import traceback

try:
    import urlparse
except ImportError:
    from urllib import parse as urlparse
import time
# we're scanning our own site
import urllib3

urllib3.disable_warnings()

# get config file for emailing a user the report
try:
    from ConfigParser import SafeConfigParser as ConfigParser  # Python 2
except ImportError:
    from configparser import ConfigParser  # Python 3

logger = _logging.getLogger("site_scan")
logger.setLevel(_logging.INFO)
_log_handler = _logging.StreamHandler(sys.stderr)
_log_format = _logging.Formatter('%(levelname)s [%(asctime).19s] %(message)s')
_log_handler.setFormatter(_log_format)
logger.addHandler(_log_handler)

try:
    import lxml

    PARSER = "lxml"
except ImportError:
    PARSER = "html.parser"
    logger.info("lxml wasn't available. Falling back on %s", PARSER)

try:
    config = ConfigParser({
        'subject': None,
        'region': 'us-east-1',
    })
    config.read('site_scan.conf')
    SES_ACCESS = config.get('ses', 'access')
    SES_SECRET = config.get('ses', 'secret')
    SES_REGION = config.get('ses', 'region')
    SUBJECT = config.get('ses', 'subject')
    FROM_ADDR = config.get('ses', 'from_addr')
    TO_ADDRS = config.get('ses', 'to_addrs').split(',')
except Exception as ex:
    logger.warning('Cache warming mode! Since no suitable configuration file was found (%s), no email '
                   'will be sent at the end.', ex)

ses = boto3.client(
    'ses',
    aws_access_key_id=SES_ACCESS,
    aws_secret_access_key=SES_SECRET,
    region_name=SES_REGION
)

SESSION = requests.Session()


class Page(object):
    __slots__ = ('url', 'source', 'status', 'time')

    def __init__(self, url, source, status=None, time=None):
        self.url = url
        self.source = source
        self.status = status
        self.time = time

    def __hash__(self):
        return hash(self.url)

    def __eq__(self, other):
        try:
            return self.url == other.url
        except:
            return False

    def __repr__(self):
        return "Page(%s, source=%s, status=%s, time=%s)" % (self.url, self.source, self.status, self.time)

    def __str__(self):
        if self.status:
            return '%s: %s from %s' % (self.status, self.url, self.source)
        return 'Unscanned: %s from %s' % (self.url, self.source)


def check_sitemap(sitemap_url):
    """Given a URL to a sitemap, returns all the URLs contained within."""
    response = requests.get(sitemap_url)
    soup = None
    for parser in ["lxml-xml", "html.parser"]:
        try:
            soup = BeautifulSoup(response.text, parser, parse_only=SoupStrainer('loc'))
            break
        except FeatureNotFound:
            logger.info("Couldn't use %s parser.", parser)
    urls = {loc.text for loc in soup}
    return urls


def _scan_page_safety(page):
    max_attempts = 10
    for attempt in range(0, max_attempts):  # try 10 times to do this
        try:
            return scan_page(page)
        except Exception:
            logger.error("Exception happened while scanning page %s ... attempt %s", page.url, attempt + 1)
            if attempt == max_attempts - 1:
                logger.error("Attempted %s times to scan %s ... not trying again :(", max_attempts, page.url)
            logger.error(traceback.format_exc())


def scan_page(page):
    scheme, domain, path = urlparse.urlparse(page.url)[:3]
    base_urls = [domain]
    if domain.startswith('www.'):  # scan the non-www version of this site too
        base_urls.append(domain[4:])
    base_urls = tuple(base_urls)
    links = set()
    with SESSION.get(page.url, stream=True, verify=False) as resp:
        if resp.status_code == 200 and 'text/html' in resp.headers['Content-Type'].lower():
            soup = BeautifulSoup(resp.text, PARSER, parse_only=SoupStrainer('a'))
            logger.info('reading the response for %s as it was text/html', page.url)
            for a in soup:
                try:
                    href = a['href']
                except (KeyError, TypeError):
                    continue
                href = href.split('#', 1)[0]
                if not href or href.startswith(('mailto:', 'tel:')):
                    continue  # not actual links to pages
                else:
                    href = urlparse.urljoin(page.url, href)
                if not href.split('://', 1)[1].startswith(base_urls):  # remove the scheme://
                    continue  # this is not a path on our website, do not follow
                links.add(Page(href, source=page.url))
        else:
            logger.info('skipped content for %s the mime type was %s and response code was %s',
                        page.url, resp.headers['Content-Type'], resp.status_code)
        page.status = resp.status_code
    return links


def scan_website(site_url, threads=(cpu_count() * 2)):
    start_time = time.time()
    pool_size = max(adapters.DEFAULT_POOLSIZE, int(threads * 1.2))
    logger.info("Scanning %s using %d threads and an HTTP connection pool size of %d" % (site_url, threads, pool_size))

    adapter = adapters.HTTPAdapter(pool_connections=pool_size, pool_maxsize=pool_size)
    SESSION.mount("http", adapter)
    found_urls = set()
    scanned_urls = set()
    if site_url.endswith('.xml'):
        # assume this is a sitemap
        for url in check_sitemap(site_url):
            found_urls.add(Page(url, source=site_url))
    else:
        found_urls.update(scan_page(Page(site_url, 'given')))
    pool = Pool(threads)

    while True:
        remaining_urls = found_urls - scanned_urls
        if not remaining_urls:  # finished with the website
            break
        logger.info("URLs to Scan (%s)", len(remaining_urls))
        scans = pool.map(_scan_page_safety, remaining_urls)
        scanned_urls |= remaining_urls
        logger.info("URLs scanned (%s)", len(scanned_urls))

        # add links found on pages to our pool of found_urls
        for links in scans:
            if links:  # might return None if the page errored out multiple times
                for page in links:
                    found_urls.add(page)  # adds the page for scanning if it doesn't already exist
    end_time = time.time()
    duration = end_time - start_time
    if duration >= 3600:
        elapsed_time = "%.2f hours" % (duration / 3600)
    elif duration >= 120:
        elapsed_time = "%.2f minutes" % (duration / 60)
    else:
        elapsed_time = "%.2f seconds" % duration
    result_message = "Finished. Scanned %d pages in %s." % (len(scanned_urls), elapsed_time)
    logger.info(result_message)

    body = StringIO()
    base_url = '%s://%s' % urlparse.urlparse(site_url)[:2]
    body.write('Scanned %s pages on %s%s' % (len(scanned_urls), base_url, os.linesep * 2))
    errors = []
    for link in scanned_urls:
        if link.status != 200:
            logger.warning(str(link))
            errors.append(str(link))

    if errors:
        body.write('Errors were found:' + os.linesep)
        for e in errors:
            body.write(e + os.linesep)
    else:
        body.write('No errors found! :)' + (os.linesep * 2))

    body.write("%s%s" % (result_message, os.linesep))

    body = body.getvalue()
    logger.info("Sending email:\n%s", body)

    if TO_ADDRS and TO_ADDRS != ['']:
        logger.info("Sending email.")
        if SUBJECT:
            subject = SUBJECT
        else:
            subject = 'Site Check for %s' % base_url

        params = {
            "Source": FROM_ADDR,
            "Destination": {
                "ToAddresses": TO_ADDRS,
            },
            "Message": {
                "Subject": {
                    "Data": subject,
                    "Charset": "UTF-8",
                },
                "Body": {
                    "Text": {
                        "Data": body,
                        "Charset": "UTF-8",
                    }
                },
            },
        }
        try:
            ses.send_email(**params)
            # ses.send_email(FROM_ADDR, subject, body, TO_ADDRS)
            logger.info("Email sent.")
        except Exception:
            logger.error("Failed to send email:\n%s" % traceback.format_exc())


if __name__ == '__main__':

    try:
        thread_count = int(sys.argv[2])
    except (ValueError, IndexError):
        thread_count = cpu_count() * 2
    try:
        site_address = sys.argv[1]
    except IndexError:
        logger.error('No argument given. Please specify the URL of the website or sitemap you wish to check.')
        exit(1)
    else:
        scan_website(site_address, threads=thread_count)
