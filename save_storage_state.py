from playwright.sync_api import sync_playwright

with sync_playwright() as p:
   browser = p.chromium.launch(headless=False)
   page = browser.new_page()
   page.goto("https://wiki.skplanet.com/login.action")
   input("로그인 완료 후 Enter를 누르세요...")
   page.context.storage_state(path="state/wiki_storage.json")
   browser.close()
