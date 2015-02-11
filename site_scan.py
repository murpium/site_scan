#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Crawls a website, sticking to just the given domain and not following external links. Reports non-200 response codes
to the emails provided if any. Emails can be omitted if you're just interested in warming the cache.

by Phillip Stromberg
on 2015-01-27
"""

from boto import connect_ses
from bs4 import BeautifulSoup, SoupStrainer
from contextlib import closing
import logging
from multiprocessing.dummy import Pool
import os
import requests
from StringIO import StringIO
import sys
import traceback
import urlparse


# get config file for emailing a user the report
from ConfigParser import RawConfigParser, NoSectionError
try:
    config = RawConfigParser({'subject': None})
    config.read('site_scan.conf')
    SES_ACCESS = config.get('ses', 'access')
    SES_SECRET = config.get('ses', 'secret')
    SUBJECT = config.get('ses', 'subject')
    FROM_ADDR = config.get('ses', 'from_addr')
    TO_ADDRS = config.get('ses', 'to_addrs').split(',')
except Exception as ex:
    logging.warn('Cache warming mode! Since no suitable configuration file was found (%s), '
                 'no email will be sent at the end.', ex.message)

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
    soup = BeautifulSoup(response.text, parse_only=SoupStrainer('loc'))
    urls = {loc.text for loc in soup}
    return urls


def _scan_page_safety(page):
    max_attempts = 10
    for attempt in range(0, max_attempts):  # try 10 times to do this
        try:
            return scan_page(page)
        except Exception as ex:
            logging.error("Exception happened while scanning page %s ... attempt %s", page.url, attempt + 1)
            if attempt == max_attempts - 1:
                logging.error("Attempted %s times to scan %s ... not trying again :(", max_attempts, page.url)
            logging.error(traceback.format_exc())

def scan_page(page):
    scheme, domain, path = urlparse.urlparse(page.url)[:3]
    base_urls = [domain]
    if domain.startswith('www.'):  # scan the non-www version of this site too
        base_urls.append(domain[4:])
    base_urls = tuple(base_urls)
    links = set()
    with closing(SESSION.get(page.url, stream=True)) as resp:
        if resp.status_code == 200 and 'text/html' in resp.headers['Content-Type'].lower():
            soup = BeautifulSoup(resp.text, parse_only=SoupStrainer('a'))
            logging.info('reading the response for %s as it was text/html', page.url)
            for a in soup:
                try:
                    href = a['href']
                except KeyError:
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
            logging.info('skipped content for %s the mime type was %s and response code was %s',
                         page.url, resp.headers['Content-Type'], resp.status_code)
        page.status = resp.status_code
    return links


def scan_website(site_url, threads=10):
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
        logging.info("URLs to Scan (%s)", len(remaining_urls))
        scans = pool.map(_scan_page_safety, remaining_urls)
        scanned_urls |= remaining_urls
        logging.info("URLs scanned (%s)", len(scanned_urls))

        # add links found on pages to our pool of found_urls
        for links in scans:
            if links:  # might return None if the page errored out multiple times
                for page in links:
                    found_urls.add(page)  # adds the page for scanning if it doesn't already exist

    logging.info("Finished. Scanned %s pages." % len(scanned_urls))

    body = StringIO()
    base_url = '%s://%s' % urlparse.urlparse(site_url)[:2]
    body.write('Scanned %s pages on %s%s' % (len(scanned_urls), base_url, os.linesep * 2))
    errors = []
    for link in scanned_urls:
        if link.status != 200:
            logging.warning(str(link))
            errors.append(str(link))

    if errors:
        body.write('Errors were found:' + os.linesep)
        for e in errors:
            body.write(e + os.linesep)
    else:
        body.write('No errors found! :)' + os.linesep)

    body = body.getvalue()
    logging.info(body)

    if TO_ADDRS and TO_ADDRS != ['']:
        logging.info("Sending email.")
        ses = connect_ses(SES_ACCESS, SES_SECRET)
        if SUBJECT:
            subject = SUBJECT
        else:
            subject = 'Site Check for %s' % base_url
        ses.send_email(FROM_ADDR, subject, body, TO_ADDRS)
        logging.info("Email sent.")

if __name__ == '__main__':
    logging.getLogger().setLevel(logging.INFO)
    try:
        threads = int(sys.argv[2])
    except (ValueError, IndexError):
        threads = 10
    try:
        site_address = sys.argv[1]
    except IndexError:
        logging.error('No argument given. Please specify the URL of the website or sitemap you wish to check.')
        exit(1)
    else:
        scan_website(site_address, threads=threads)