import json
import subprocess
from pathlib import Path


def run_node_script(tmp_path, content: str) -> str:
    script_path = tmp_path / "run.js"
    script_path.write_text(content, encoding="utf-8")
    completed = subprocess.run(["node", str(script_path)], capture_output=True, text=True, check=True)
    return completed.stdout.strip()


def test_dns_drift_confirmation_sets_force(tmp_path):
    repo_root = Path(__file__).resolve().parent.parent
    app_js = repo_root / "mcbridge" / "mcbridge" / "web" / "static" / "js" / "app.js"
    output = json.loads(
        run_node_script(
            tmp_path,
            f"""
const fs = require("fs");
const vm = require("vm");

const code = fs.readFileSync("{app_js.as_posix()}", "utf8");
const sandbox = {{
  console,
  setTimeout,
  clearTimeout,
  document: {{
    addEventListener: () => {{}},
    getElementById: () => null,
  }},
}};

vm.createContext(sandbox);
vm.runInContext(code, sandbox);

vm.runInContext(
  `
let capturedConfirm = "";
let capturedPost = null;

dashboardState.latestDnsStatus = {{
  status: "warning",
  mismatch_summary: "dns drift",
}};

dashboardElements.dnsRedirectInput = {{ value: "redirect.test" }};
dashboardElements.dnsTargetInput = {{ value: "1.2.3.4" }};

confirm = (message) => {{
  capturedConfirm = message;
  return true;
}};

postAndRender = (url, body) => {{
  capturedPost = {{ url, body }};
  return Promise.resolve();
}};

(async () => {{
  await submitDns();
  console.log(JSON.stringify({{ confirm: capturedConfirm, post: capturedPost }}));
}})().catch((err) => {{
  console.error(err);
  process.exit(1);
}});
`,
  sandbox
);
""",
        ),
    )

    assert "DNS drift detected" in output["confirm"]
    assert output["post"]["url"] == "/dns/update"
    assert output["post"]["body"]["force"] is True


def test_upstream_password_input_not_prefilled(tmp_path):
    repo_root = Path(__file__).resolve().parent.parent
    app_js = repo_root / "mcbridge" / "mcbridge" / "web" / "static" / "js" / "app.js"
    output = json.loads(
        run_node_script(
            tmp_path,
            f"""
const fs = require("fs");
const vm = require("vm");

const code = fs.readFileSync("{app_js.as_posix()}", "utf8");
const sandbox = {{
  console,
  setTimeout,
  clearTimeout,
  document: {{
    addEventListener: () => {{}},
    getElementById: () => null,
  }},
}};

vm.createContext(sandbox);
vm.runInContext(code, sandbox);

vm.runInContext(
  `
dashboardElements.upstreamPasswordInput = {{ value: "secret" }};
dashboardElements.upstreamSsidInput = {{ value: "", readOnly: false }};
dashboardElements.upstreamPriorityInput = {{ value: "" }};
dashboardElements.upstreamSecuritySelect = {{ value: "" }};
dashboardElements.saveUpstreamBtn = {{ textContent: "" }};
dashboardElements.deleteUpstreamBtn = {{ disabled: false }};

setUpstreamSelection({{
  ssid: "Home",
  saved: true,
  security: "wpa2",
  priority: 5,
}});

console.log(
  JSON.stringify({{
    passwordValue: dashboardElements.upstreamPasswordInput.value,
    selectedSsid: upstreamState.selectedSsid,
  }})
);
`,
  sandbox
);
""",
        ),
    )

    assert output["passwordValue"] == ""
    assert output["selectedSsid"] == "Home"


def test_upstream_psk_toggle_validates_length(tmp_path):
    repo_root = Path(__file__).resolve().parent.parent
    app_js = repo_root / "mcbridge" / "mcbridge" / "web" / "static" / "js" / "app.js"
    output = json.loads(
        run_node_script(
            tmp_path,
            f"""
const fs = require("fs");
const vm = require("vm");

const code = fs.readFileSync("{app_js.as_posix()}", "utf8");
const sandbox = {{
  console,
  setTimeout,
  clearTimeout,
  document: {{
    addEventListener: () => {{}},
    getElementById: () => null,
  }},
}};

vm.createContext(sandbox);
vm.runInContext(code, sandbox);

vm.runInContext(
  `
dashboardElements.upstreamSsidInput = {{ value: "ToggleTest" }};
dashboardElements.upstreamPasswordInput = {{ value: "short" }};
dashboardElements.upstreamPriorityInput = {{ value: "1" }};
dashboardElements.upstreamSecuritySelect = {{ value: "wpa2" }};
let errorMessage = "";

try {{
  getUpstreamFormPayload();
}} catch (err) {{
  errorMessage = err.message;
}}

console.log(JSON.stringify({{ errorMessage }}));
`,
  sandbox
);
""",
        ),
    )

    assert output["errorMessage"] == "PSK must be 64 hex characters."


def test_upstream_table_omits_password_column(tmp_path):
    repo_root = Path(__file__).resolve().parent.parent
    app_js = repo_root / "mcbridge" / "mcbridge" / "web" / "static" / "js" / "app.js"
    output = json.loads(
        run_node_script(
            tmp_path,
            f"""
const fs = require("fs");
const vm = require("vm");

class Element {{
  constructor(tag) {{
    this.tagName = tag;
    this.children = [];
    this.dataset = {{}};
    this._colSpan = undefined;
    this.textContent = "";
    this.className = "";
    this.classList = {{
      add: (...args) => {{
        const current = new Set((this.className || "").split(" ").filter(Boolean));
        args.forEach((cls) => current.add(cls));
        this.className = Array.from(current).join(" ");
      }},
      remove: (...args) => {{
        const current = new Set((this.className || "").split(" ").filter(Boolean));
        args.forEach((cls) => current.delete(cls));
        this.className = Array.from(current).join(" ");
      }},
      toggle: (cls, force) => {{
        const current = new Set((this.className || "").split(" ").filter(Boolean));
        const shouldHave = force === undefined ? !current.has(cls) : !!force;
        if (shouldHave) {{
          current.add(cls);
        }} else {{
          current.delete(cls);
        }}
        this.className = Array.from(current).join(" ");
      }},
    }};
  }}
  appendChild(child) {{
    this.children.push(child);
  }}
  addEventListener() {{}}
  set colSpan(value) {{
    this._colSpan = value;
  }}
  get colSpan() {{
    return this._colSpan;
  }}
  set innerHTML(_value) {{
    this.children = [];
  }}
  get innerHTML() {{
    return "";
  }}
}}

const upstreamProfilesBody = new Element("tbody");
const code = fs.readFileSync("{app_js.as_posix()}", "utf8");
const sandbox = {{
  console,
  setTimeout,
  clearTimeout,
  upstreamProfilesBody,
  document: {{
    addEventListener: () => {{}},
    createElement: (tag) => new Element(tag),
    getElementById: () => null,
  }},
}};

vm.createContext(sandbox);
vm.runInContext(code, sandbox);

vm.runInContext(
  `
dashboardElements.upstreamProfilesBody = upstreamProfilesBody;

renderUpstreamProfiles([]);
const emptyColSpan = dashboardElements.upstreamProfilesBody.children[0].children[0].colSpan;

renderUpstreamProfiles([{{ ssid: "TestNet", priority: 1, security: "wpa2", saved: true }}]);
const row = dashboardElements.upstreamProfilesBody.children[0];

console.log(
  JSON.stringify({{
    childCount: row.children.length,
    emptyColSpan,
  }})
);
`,
  sandbox
);
""",
        ),
    )

    assert output["childCount"] == 5
    assert output["emptyColSpan"] == 5
