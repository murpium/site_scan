# Site Scan

Site Scan is a Python script for crawling a given domain. It can send an email about non-200 HTTP response code pages it found or it can just be used as a cache warmer.

### Version
0.1

### Requires
* [beautifulsoup4] - An HTML parser for finding anchor tags
* [boto] - Amazon Web Services library for sending SES emails
* [requests] - For getting the content and status codes of HTTP(S)

### Installation
You should be able to do a pip install -r requirements.txt after creating a virtual environment and be ready to go.

```sh
site_scan.py http://www.example.com
```
or you can specify a number of threads (the default is 10)
```sh
site_scan.py http://www.example.com 8
```
**If you want an email report sent to you when the scan is complete**, fill out ```site_scan.conf.example``` with your 
information and rename to ```site_scan.conf```

License
----
[Apache 2.0]

Author
----
[@phistrom]

[beautifulsoup4]:http://www.crummy.com/software/BeautifulSoup/bs4/doc/
[boto]:https://github.com/boto/boto
[requests]:https://github.com/kennethreitz/requests
[Apache 2.0]:http://www.apache.org/licenses/LICENSE-2.0
[@phistrom]:https://twitter.com/phistrom