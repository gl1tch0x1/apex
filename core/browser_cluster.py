import asyncio
import logging
from urllib.parse import quote_plus

from playwright.async_api import async_playwright

class BrowserCluster:
    def __init__(self, size=2, browsers=['chromium', 'firefox', 'webkit']):
        self.size = size
        self.browsers = browsers

    async def run(self, tasks):
        results = []
        async with async_playwright() as p:
            browser_type = self.browsers[0]
            browser = await getattr(p, browser_type).launch()
            semaphore = asyncio.Semaphore(self.size)

            async def worker(task):
                async with semaphore:
                    return await self._execute_task(browser, task)

            batch_results = await asyncio.gather(*[worker(t) for t in tasks], return_exceptions=True)
            results.extend([r for r in batch_results if not isinstance(r, Exception)])
            await browser.close()

        return results

    async def _execute_task(self, browser, task):
        context = await browser.new_context()
        try:
            page = await context.new_page()
            await page.add_init_script("""
                window.__xss = false;
                window.__alerts = [];
                const old_eval = window.eval;
                const old_alert = window.alert;
                window.eval = function() {
                    window.__xss = true;
                    return old_eval.apply(this, arguments);
                };
                window.alert = function(msg) {
                    window.__alerts.push(msg);
                    return old_alert.apply(this, arguments);
                };
            """)

            url = task.get('url')
            param = task.get('param')
            payload = task.get('payload')
            full_url = f"{url}?{param}={quote_plus(str(payload))}"
            await page.goto(full_url, timeout=30000)

            xss_detected = await page.evaluate("window.__xss")
            alerts = await page.evaluate("window.__alerts")

            result = {
                "url": full_url,
                "type": "DOM XSS",
                "vulnerable": xss_detected or len(alerts) > 0,
                "payload": payload,
                "alerts": alerts
            }

            logging.info(f"Tested {full_url}: Vulnerable={result['vulnerable']}")
            return result

        except Exception as e:
            logging.error(f"Error testing {task}: {e}")
            return {"url": task.get('url'), "error": str(e)}
        finally:
            await context.close()