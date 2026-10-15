"""Hosted-only browser acceptance against built WebUI and synthetic API data."""
import json
import os
from pathlib import Path
from urllib.parse import urlparse, parse_qs

from playwright.sync_api import sync_playwright, expect

if os.environ.get('GITHUB_ACTIONS') != 'true':
    raise SystemExit('Run browser acceptance only on GitHub-hosted CI')

platform_id = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
platform = dict(id=platform_id, name='Fixture', sticky_ttl='24h', regex_filters=[],
                region_filters=[], routable_node_count=1, reverse_proxy_miss_action='TREAT_AS_EMPTY',
                reverse_proxy_empty_account_behavior='RANDOM', reverse_proxy_fixed_account_header='',
                allocation_policy='BALANCED', passive_circuit_breaker_disabled=False,
                updated_at='2026-10-15T00:00:00Z')
base_lease = dict(platform_id=platform_id, account='legacy-42', node_hash='a'*32,
                  node_tag='fixture/node', egress_ip='192.0.2.1',
                  expiry='2030-01-01T00:00:00Z', last_accessed='2026-10-15T00:00:00Z')
output = Path(os.environ['RUNNER_TEMP']) / 'lease-ui-evidence'
output.mkdir(exist_ok=True)
with sync_playwright() as pw:
    browser = pw.chromium.launch()
    for width in (390, 1440):
        lease = dict(base_lease)
        changes = []
        context = browser.new_context(viewport={'width': width, 'height': 900}, locale='zh-CN')
        context.add_init_script("localStorage.setItem('resin_admin_token','synthetic'); localStorage.setItem('resin.webui.locale','zh-CN');")
        def api(route):
            request = route.request
            parsed = urlparse(request.url)
            path = parsed.path
            if path.endswith('/display-name'):
                assert request.method == 'PATCH'
                assert path.endswith('/legacy-42/display-name')
                payload = request.post_data_json
                assert set(payload) == {'display_name'}
                lease['display_name'] = payload['display_name']
                changes.append(payload['display_name'])
                data = lease
            elif path.endswith('/leases'):
                query = parse_qs(parsed.query)
                search = query.get('search', [''])[0].lower()
                assert 'account' not in query
                rows = [lease] if search in lease['account'].lower() or search in lease.get('display_name', '').lower() else []
                data = {'items': rows, 'total': len(rows), 'limit': 10, 'offset': 0}
            elif path == '/api/v1/platforms/' + platform_id:
                data = platform
            else:
                data = {'items': [], 'total': 0, 'limit': 10, 'offset': 0}
            route.fulfill(status=200, content_type='application/json', body=json.dumps(data))
        context.route('**/api/v1/**', api)
        page = context.new_page()
        page.on('pageerror', lambda error: print('WebUI error:', error))
        page.goto('http://127.0.0.1:4173/ui/platforms/' + platform_id + '?tab=ops')
        page.screenshot(path=str(output / f'initial-{width}.png'), full_page=True)
        expect(page.get_by_text('legacy-42', exact=True)).to_be_visible()
        page.once('dialog', lambda dialog: dialog.accept('wd-account-42'))
        page.get_by_role('button', name='设置名称', exact=True).click()
        expect(page.get_by_role('button', name='wd-account-42', exact=True)).to_be_visible()
        search = page.get_by_role('textbox', name='搜索账号或显示名称', exact=True)
        for term in ('wd-account-42', 'legacy-42'):
            search.fill(term)
            expect(page.get_by_text('legacy-42', exact=True)).to_be_visible()
            page.wait_for_timeout(450)
            expect(page.get_by_role('button', name='wd-account-42', exact=True)).to_be_visible()
        page.screenshot(path=str(output / f'labels-{width}.png'), full_page=True)
        search.fill('')
        page.wait_for_timeout(450)
        page.once('dialog', lambda dialog: dialog.accept(''))
        page.get_by_role('button', name='wd-account-42', exact=True).click()
        expect(page.get_by_role('button', name='设置名称', exact=True)).to_be_visible()
        assert changes == ['wd-account-42', '']
        assert {k: lease[k] for k in base_lease} == base_lease
        context.close()
    browser.close()
print('Lease UI edit, old/new search, clear and identity preservation passed at 390/1440px')
