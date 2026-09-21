import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import yaml


ROOT = Path(__file__).resolve().parent


class SubscriptionTest(unittest.TestCase):
    def test_all_regions_and_fail_closed(self):
        with tempfile.TemporaryDirectory(prefix="proxy-subscription-test.") as directory:
            work = Path(directory)
            config = json.loads((ROOT / "examples/xray-proxy.json.example").read_text())
            identifier = "00000000-0000-4000-8000-000000000001"
            for index, inbound in enumerate(config["inbounds"]):
                inbound["settings"]["clients"][0]["id"] = identifier
                network = inbound["streamSettings"]["network"]
                inbound["streamSettings"][network + "Settings"]["path"] = (
                    f"/{network}/{index + 1:064x}"
                )
            template = config["inbounds"][-1]
            for index, region in enumerate(("sg", "de", "cn"), start=3):
                inbound = copy.deepcopy(template)
                inbound.update(tag=f"proxy-ws-{region}", port=13100 + index)
                inbound["streamSettings"] = {
                    "network": "xhttp", "security": "none",
                    "xhttpSettings": {"path": f"/ws/{index + 3:064x}", "mode": "stream-up"},
                }
                config["inbounds"].append(inbound)
                outbound = copy.deepcopy(config["outbounds"][-1])
                outbound["tag"] = f"resin-{region}"
                outbound["settings"]["servers"][0]["users"][0]["user"] = f"Proxy{region.upper()}"
                config["outbounds"].append(outbound)
                config["routing"]["rules"].append({
                    "type": "field", "inboundTag": [inbound["tag"]],
                    "outboundTag": outbound["tag"],
                })

            token = "a" * 64
            config_file = work / "config.json"
            token_file = work / "token"
            token_file.write_text(token + "\n")
            output = work / "out"
            url_file = work / "url"
            env = dict(os.environ, XRAY_PROXY_CONFIG=str(config_file),
                       XRAY_SITE_POLICY=str(work / "no-site-policy.json"),
                       XRAY_ROTATION_POLICY=str(work / "no-rotation-policy.json"),
                       XRAY_SUBSCRIPTION_TOKEN_FILE=str(token_file),
                       XRAY_SUBSCRIPTION_OUTPUT_DIR=str(output),
                       XRAY_SUBSCRIPTION_URL_FILE=str(url_file))

            def render(value):
                config_file.write_text(json.dumps(value))
                return subprocess.run(["bash", str(ROOT / "render-proxy-subscription.sh")],
                                      env=env, capture_output=True).returncode

            self.assertEqual(render(config), 0)
            subscription = output / (token + ".yaml")
            good_yaml, good_url = subscription.read_bytes(), url_file.read_bytes()
            parsed = yaml.safe_load(good_yaml)
            names = ["weesai.com-vless-443", "weesai.com-vless-443-ws",
                     "HK-Auto", "JP-Auto", "US-Auto", "CN-Auto", "DE-Auto", "SG-Auto"]
            self.assertEqual([p["name"] for p in parsed["proxies"]], names)
            groups = {group["name"]: group for group in parsed["proxy-groups"]}
            self.assertEqual(groups["PROXY"]["type"], "select")
            self.assertEqual(groups["PROXY"]["proxies"][0], "Auto-Fast")
            self.assertEqual(groups["Auto-Fast"]["type"], "url-test")
            self.assertEqual(groups["Auto-Fast"]["proxies"], ["US-Auto", "JP-Auto", "HK-Auto"])
            for name in names[:2]:
                self.assertIn(name, groups["PROXY"]["proxies"])
            self.assertEqual(groups["Auto-Region"]["proxies"], names[2:])
            self.assertEqual(parsed["rules"], ["MATCH,PROXY"])
            self.assertTrue(parsed["profile"]["store-selected"])
            self.assertEqual(good_url.decode(), f"https://weesai.com/sub/{token}.yaml\n")
            for index, proxy in enumerate(parsed["proxies"]):
                self.assertEqual(proxy["server"], "weesai.com")
                self.assertEqual(proxy["port"], 443)
                self.assertEqual(proxy["uuid"], identifier)
                self.assertTrue(proxy["tls"])
                self.assertEqual(proxy["udp"], index < 2)
                if index >= 2:
                    tag = "proxy-ws-" + proxy["name"][:2].lower()
                    inbound = next(i for i in config["inbounds"] if i["tag"] == tag)
                    self.assertEqual(proxy["network"], inbound["streamSettings"]["network"])
                    network = proxy["network"]
                    self.assertEqual(proxy[network + "-opts"]["path"], inbound["streamSettings"][network + "Settings"]["path"])
                    if network == "xhttp":
                        self.assertEqual(proxy["alpn"], ["h2"])
            self.assertEqual(parsed["proxies"][0]["xhttp-opts"]["mode"], "stream-up")
            self.assertEqual(parsed["proxies"][0]["alpn"], ["h2"])

            self.assertEqual(render(config), 0)
            self.assertEqual(subscription.read_bytes(), good_yaml)
            self.assertEqual(url_file.read_bytes(), good_url)

            invalid = []
            bad = copy.deepcopy(config)
            bad["inbounds"] = [i for i in bad["inbounds"]
                               if i["tag"] not in ("proxy-ws-hk", "proxy-ws-jp", "proxy-ws-us")]
            invalid.append(bad)
            bad = copy.deepcopy(config)
            bad["inbounds"][-1]["streamSettings"]["xhttpSettings"]["path"] = "/invalid"
            invalid.append(bad)
            bad = copy.deepcopy(config)
            bad["inbounds"][-1]["settings"]["clients"][0]["id"] = "wrong"
            invalid.append(bad)
            bad = copy.deepcopy(config)
            bad["inbounds"][-1]["port"] = bad["inbounds"][-2]["port"]
            invalid.append(bad)
            bad = copy.deepcopy(config)
            bad["routing"]["rules"][-1]["outboundTag"] = "direct"
            invalid.append(bad)
            bad = copy.deepcopy(config)
            bad["outbounds"][-1]["settings"]["servers"][0]["users"][0]["user"] += ".sticky"
            invalid.append(bad)
            for value in invalid:
                self.assertNotEqual(render(value), 0)
                self.assertEqual(subscription.read_bytes(), good_yaml)
                self.assertEqual(url_file.read_bytes(), good_url)


if __name__ == "__main__":
    unittest.main()
