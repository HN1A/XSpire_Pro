# XSpire Pro - Advanced XSS Scanner  
XSpire Pro هي أداة متقدمة لفحص ثغرات XSS تشمل فحص WebSocket، الزحف التلقائي، تحليل النماذج، توليد تقارير HTML، ودعم Tor والـ Proxy.  
XSpire Pro is an advanced XSS vulnerability scanner with support for WebSocket testing, auto-crawling, form analysis, HTML report generation, and Tor/Proxy usage.

---

## الميزات | Features
- فحص شامل لـ GET و POST  
  Full GET and POST scanning  
- كشف حماية CSP, XSS-Protection, WAF  
  Detection of CSP, XSS-Protection, and WAFs  
- تحليل DOM XSS و WebSocket  
  DOM XSS and WebSocket analysis  
- كشف النقاط المنعكسة وتقييم المخاطر  
  Reflection point detection and risk evaluation  
- دعم Tor ووكيل SOCKS/HTTP  
  Support for Tor and HTTP/SOCKS proxy  
- دعم متعدد الخيوط (Multithreading)  
  Multithreaded scanning  
- تقارير HTML مفصلة  
  Detailed HTML reports

---
##التثبت | Verification 
```bash

git clone https://github.com/HN1A/XSpire_Pro.git
pip install-r Requirements.txt
python XSpire_Pro.py --help 
## المتطلبات | Requirements

قم بتثبيت المكتبات التالية:  
Install the following Python packages:

```bash
pip install requests rich beautifulsoup4 fake-useragent PySocks stem websocket-client




طريقة التشغيل | How to Run

فحص GET | GET Scan:

python XSpire_Pro.py --url http://example.com

فحص POST | POST Scan:

python XSpire_Pro.py --post http://example.com/login --data "user=admin&pass=test"


---

خيارات إضافية | Additional Options:

--crawl: الزحف التلقائي | Enable auto-crawling

--proxy: استخدام وكيل | Use a proxy (e.g., http://127.0.0.1:8080)

--tor: استخدام Tor | Use Tor for anonymity

--stealth: الوضع المتخفي | Enable stealth mode (random delays)

--random-agent: User-Agent عشوائي | Use a random User-Agent

--report: إنشاء تقرير HTML | Generate HTML report

--threads: عدد الخيوط (افتراضي 5) | Number of threads (default: 5)

--list-files: عرض ملفات الحمولات | List available payload files

--help-commands: عرض جميع الأوامر | Show all command-line options
_______

مثال شامل | Full Example

python XSpire_Pro.py --url http://target.com --crawl --stealth --random-agent --report report.html


---

ملاحظات | Notes

يجب تشغيل خدمة Tor محلياً عند استخدام --tor
Ensure Tor is running locally when using --tor

الأداة مخصصة للاستخدام التعليمي واختبارات الاختراق المصرح بها
This tool is intended for educational and authorized penetration testing only.

