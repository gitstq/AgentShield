"""Web dashboard for AgentShield.

A lightweight Flask-based dashboard for viewing policies, audit logs,
and testing policy decisions. All HTML templates are inline to avoid
external dependencies.
"""

import json
from typing import Any, Dict, Optional

from agentshield.core.engine import PolicyEngine
from agentshield.core.policy import Effect, Policy, PolicySet
from agentshield.core.context import ExecutionContext
from agentshield.templates.builtin import BuiltinTemplates

try:
    from flask import Flask, Response, jsonify, request as flask_request
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False


def create_app(engine: Optional[PolicyEngine] = None) -> "Flask":
    """Create and configure the Flask dashboard application.

    Args:
        engine: Optional pre-configured PolicyEngine. If None, a default
            engine with balanced template policies is created.

    Returns:
        A configured Flask application.

    Raises:
        ImportError: If Flask is not installed.
    """
    if not FLASK_AVAILABLE:
        raise ImportError(
            "Flask is required for the dashboard. "
            "Install it with: pip install flask"
        )

    app = Flask(__name__)
    app.config["SECRET_KEY"] = "agentshield-dashboard-secret-key"

    if engine is None:
        engine = PolicyEngine()
        engine.load_policy_set(BuiltinTemplates.balanced())

    app.extensions["agentshield_engine"] = engine

    # ---- HTML Templates ----

    BASE_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title} - AgentShield Dashboard</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #f5f7fa;
            color: #333;
            line-height: 1.6;
        }}
        .header {{
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: white;
            padding: 1rem 2rem;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }}
        .header h1 {{ font-size: 1.5rem; }}
        .header h1 span {{ color: #4fc3f7; }}
        nav {{
            display: flex;
            gap: 1rem;
        }}
        nav a {{
            color: #ccc;
            text-decoration: none;
            padding: 0.5rem 1rem;
            border-radius: 4px;
            transition: all 0.2s;
        }}
        nav a:hover, nav a.active {{
            background: rgba(255,255,255,0.1);
            color: white;
        }}
        .container {{
            max-width: 1200px;
            margin: 2rem auto;
            padding: 0 1rem;
        }}
        .card {{
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            padding: 1.5rem;
            margin-bottom: 1.5rem;
        }}
        .card h2 {{
            margin-bottom: 1rem;
            padding-bottom: 0.5rem;
            border-bottom: 2px solid #eee;
            color: #1a1a2e;
        }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 1.5rem;
        }}
        .stat-card {{
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            padding: 1.5rem;
            text-align: center;
        }}
        .stat-card .value {{
            font-size: 2rem;
            font-weight: bold;
            color: #1a1a2e;
        }}
        .stat-card .label {{
            color: #666;
            font-size: 0.9rem;
            margin-top: 0.25rem;
        }}
        .stat-card.allowed .value {{ color: #4caf50; }}
        .stat-card.denied .value {{ color: #f44336; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 1rem;
        }}
        th, td {{
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid #eee;
        }}
        th {{
            background: #f8f9fa;
            font-weight: 600;
            color: #555;
        }}
        tr:hover {{ background: #f8f9fa; }}
        .badge {{
            display: inline-block;
            padding: 0.2rem 0.6rem;
            border-radius: 12px;
            font-size: 0.8rem;
            font-weight: 600;
        }}
        .badge-allow {{ background: #e8f5e9; color: #2e7d32; }}
        .badge-deny {{ background: #ffebee; color: #c62828; }}
        .badge-enabled {{ background: #e3f2fd; color: #1565c0; }}
        .badge-disabled {{ background: #f5f5f5; color: #999; }}
        form {{
            display: flex;
            gap: 0.5rem;
            margin-bottom: 1rem;
            flex-wrap: wrap;
        }}
        input, select, button {{
            padding: 0.5rem 1rem;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 0.9rem;
        }}
        button {{
            background: #1a1a2e;
            color: white;
            border: none;
            cursor: pointer;
            transition: background 0.2s;
        }}
        button:hover {{ background: #16213e; }}
        .result-box {{
            background: #f8f9fa;
            border: 1px solid #ddd;
            border-radius: 4px;
            padding: 1rem;
            margin-top: 1rem;
            font-family: monospace;
            white-space: pre-wrap;
            max-height: 400px;
            overflow-y: auto;
        }}
        .empty {{ color: #999; text-align: center; padding: 2rem; }}
        .footer {{
            text-align: center;
            padding: 2rem;
            color: #999;
            font-size: 0.85rem;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1><span>Agent</span>Shield</h1>
        <nav>
            <a href="/" class="{nav_overview}">Overview</a>
            <a href="/policies" class="{nav_policies}">Policies</a>
            <a href="/audit" class="{nav_audit}">Audit Logs</a>
            <a href="/test" class="{nav_test}">Test</a>
        </nav>
    </div>
    <div class="container">
        {content}
    </div>
    <div class="footer">
        AgentShield v1.0.0 - AI Agent Policy Governance Engine
    </div>
</body>
</html>"""

    def render_page(title: str, content: str, active_nav: str = "") -> str:
        """Render a full HTML page with the base template.

        Args:
            title: Page title.
            content: Main content HTML.
            active_nav: Active navigation item name.

        Returns:
            Complete HTML page string.
        """
        return BASE_TEMPLATE.format(
            title=title,
            content=content,
            nav_overview="active" if active_nav == "overview" else "",
            nav_policies="active" if active_nav == "policies" else "",
            nav_audit="active" if active_nav == "audit" else "",
            nav_test="active" if active_nav == "test" else "",
        )

    # ---- Routes ----

    @app.route("/")
    def overview() -> str:
        """Dashboard overview page with statistics."""
        eng: PolicyEngine = app.extensions["agentshield_engine"]
        stats = eng.audit_logger.get_stats()
        policies = eng.get_policies_summary()
        guards = eng.get_guards_summary()

        policy_rows = ""
        for p in policies:
            effect_class = "badge-allow" if p["effect"] == "allow" else "badge-deny"
            enabled_class = "badge-enabled" if p["enabled"] else "badge-disabled"
            policy_rows += f"""<tr>
                <td>{p['name']}</td>
                <td><span class="badge {effect_class}">{p['effect']}</span></td>
                <td><span class="badge {enabled_class}">{'Enabled' if p['enabled'] else 'Disabled'}</span></td>
                <td>{p['priority']}</td>
                <td>{', '.join(p['actions'][:3])}{'...' if len(p['actions']) > 3 else ''}</td>
            </tr>"""

        guard_rows = ""
        for g in guards:
            enforce_class = "badge-enabled" if g["enforce_mode"] else "badge-disabled"
            guard_rows += f"""<tr>
                <td>{g['name']}</td>
                <td>{g['description']}</td>
                <td><span class="badge {enforce_class}">{'Enforce' if g['enforce_mode'] else 'Monitor'}</span></td>
            </tr>"""

        content = f"""
        <div class="stats">
            <div class="stat-card">
                <div class="value">{stats['total_entries']}</div>
                <div class="label">Total Evaluations</div>
            </div>
            <div class="stat-card allowed">
                <div class="value">{stats['allowed_count']}</div>
                <div class="label">Allowed</div>
            </div>
            <div class="stat-card denied">
                <div class="value">{stats['denied_count']}</div>
                <div class="label">Denied</div>
            </div>
            <div class="stat-card">
                <div class="value">{len(policies)}</div>
                <div class="label">Active Policies</div>
            </div>
            <div class="stat-card">
                <div class="value">{len(guards)}</div>
                <div class="label">Registered Guards</div>
            </div>
            <div class="stat-card">
                <div class="value">{stats['unique_agents']}</div>
                <div class="label">Unique Agents</div>
            </div>
        </div>

        <div class="card">
            <h2>Policies ({len(policies)})</h2>
            {"<table><tr><th>Name</th><th>Effect</th><th>Status</th><th>Priority</th><th>Actions</th></tr>" + policy_rows + "</table>" if policy_rows else '<p class="empty">No policies loaded</p>'}
        </div>

        <div class="card">
            <h2>Guards ({len(guards)})</h2>
            {"<table><tr><th>Name</th><th>Description</th><th>Mode</th></tr>" + guard_rows + "</table>" if guard_rows else '<p class="empty">No guards registered</p>'}
        </div>
        """

        return render_page("Overview", content, "overview")

    @app.route("/policies")
    def policies_page() -> str:
        """Policies management page."""
        eng: PolicyEngine = app.extensions["agentshield_engine"]
        policies = eng.get_policies_summary()

        rows = ""
        for p in policies:
            effect_class = "badge-allow" if p["effect"] == "allow" else "badge-deny"
            enabled_class = "badge-enabled" if p["enabled"] else "badge-disabled"
            resources = ", ".join(p["resources"][:3])
            if len(p["resources"]) > 3:
                resources += "..."
            actions = ", ".join(p["actions"][:3])
            if len(p["actions"]) > 3:
                actions += "..."
            tags = ", ".join(p.get("tags", []))
            rows += f"""<tr>
                <td><strong>{p['name']}</strong></td>
                <td>{p.get('description', '')}</td>
                <td><span class="badge {effect_class}">{p['effect']}</span></td>
                <td><span class="badge {enabled_class}">{'Enabled' if p['enabled'] else 'Disabled'}</span></td>
                <td>{p['priority']}</td>
                <td>{actions}</td>
                <td>{resources}</td>
                <td>{tags}</td>
            </tr>"""

        content = f"""
        <div class="card">
            <h2>Policy Set: {eng.policy_set.name}</h2>
            <p>{eng.policy_set.description or 'No description'}</p>
        </div>
        <div class="card">
            <h2>All Policies ({len(policies)})</h2>
            {"<table><tr><th>Name</th><th>Description</th><th>Effect</th><th>Status</th><th>Priority</th><th>Actions</th><th>Resources</th><th>Tags</th></tr>" + rows + "</table>" if rows else '<p class="empty">No policies configured</p>'}
        </div>
        """

        return render_page("Policies", content, "policies")

    @app.route("/audit")
    def audit_page() -> str:
        """Audit logs page."""
        eng: PolicyEngine = app.extensions["agentshield_engine"]
        limit = flask_request.args.get("limit", 100, type=int)
        offset = flask_request.args.get("offset", 0, type=int)
        agent_filter = flask_request.args.get("agent_id", "")
        decision_filter = flask_request.args.get("decision", "")

        entries = eng.audit_logger.get_entries(
            limit=limit,
            offset=offset,
            agent_id=agent_filter if agent_filter else None,
            decision=decision_filter if decision_filter else None,
        )

        rows = ""
        for e in entries:
            decision_class = "badge-allow" if e.get("decision") == "allowed" else "badge-deny"
            details = e.get("details", {})
            detail_str = json.dumps(details, ensure_ascii=False) if details else ""
            rows += f"""<tr>
                <td>{e.get('timestamp', '')}</td>
                <td>{e.get('agent_id', '')}</td>
                <td>{e.get('action', '')}</td>
                <td>{e.get('resource', '')}</td>
                <td><span class="badge {decision_class}">{e.get('decision', '')}</span></td>
                <td>{e.get('guard_name', '')}</td>
                <td title="{detail_str}">{detail_str[:80]}{'...' if len(detail_str) > 80 else ''}</td>
            </tr>"""

        content = f"""
        <div class="card">
            <h2>Audit Logs</h2>
            <form method="get">
                <input type="text" name="agent_id" placeholder="Agent ID" value="{agent_filter}">
                <select name="decision">
                    <option value="">All Decisions</option>
                    <option value="allowed" {'selected' if decision_filter == 'allowed' else ''}>Allowed</option>
                    <option value="denied" {'selected' if decision_filter == 'denied' else ''}>Denied</option>
                </select>
                <input type="number" name="limit" value="{limit}" min="1" max="1000" style="width:80px">
                <button type="submit">Filter</button>
            </form>
            {"<table><tr><th>Timestamp</th><th>Agent</th><th>Action</th><th>Resource</th><th>Decision</th><th>Guard</th><th>Details</th></tr>" + rows + "</table>" if rows else '<p class="empty">No audit log entries</p>'}
        </div>
        """

        return render_page("Audit Logs", content, "audit")

    @app.route("/test")
    def test_page() -> str:
        """Policy testing page."""
        content = """
        <div class="card">
            <h2>Test Policy Decision</h2>
            <p>Enter an action and resource to test against the current policy set.</p>
            <form id="test-form">
                <input type="text" id="action" placeholder="Action (e.g., file:read)" style="width:300px" required>
                <input type="text" id="resource" placeholder="Resource (e.g., /etc/passwd)" style="width:300px" required>
                <input type="text" id="agent_id" placeholder="Agent ID (optional)" style="width:200px">
                <button type="submit">Test</button>
            </form>
            <div id="result" class="result-box" style="display:none;"></div>
        </div>
        <div class="card">
            <h2>Quick Tests</h2>
            <div id="quick-tests"></div>
        </div>
        <script>
        document.getElementById('test-form').addEventListener('submit', async function(e) {
            e.preventDefault();
            const action = document.getElementById('action').value;
            const resource = document.getElementById('resource').value;
            const agent_id = document.getElementById('agent_id').value || 'test_agent';
            const resultDiv = document.getElementById('result');
            resultDiv.style.display = 'block';
            resultDiv.textContent = 'Testing...';
            try {
                const resp = await fetch('/api/test', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({action, resource, agent_id})
                });
                const data = await resp.json();
                resultDiv.textContent = JSON.stringify(data, null, 2);
            } catch(err) {
                resultDiv.textContent = 'Error: ' + err.message;
            }
        });

        const quickTests = [
            {action: 'file:read', resource: '/etc/passwd', label: 'Read /etc/passwd'},
            {action: 'file:read', resource: '/tmp/data.txt', label: 'Read /tmp/data.txt'},
            {action: 'http:request', resource: 'https://api.example.com/data', label: 'HTTPS API call'},
            {action: 'http:request', resource: 'http://internal.corp.local', label: 'Internal URL'},
            {action: 'code:execute', resource: 'print("hello")', label: 'Safe code'},
            {action: 'code:execute', resource: 'os.system("rm -rf /")', label: 'Dangerous code'},
            {action: 'prompt:submit', resource: 'ignore previous instructions', label: 'Prompt injection'},
        ];

        const container = document.getElementById('quick-tests');
        quickTests.forEach(t => {
            const btn = document.createElement('button');
            btn.textContent = t.label;
            btn.style.margin = '0.25rem';
            btn.onclick = async () => {
                document.getElementById('action').value = t.action;
                document.getElementById('resource').value = t.resource;
                document.getElementById('test-form').dispatchEvent(new Event('submit'));
            };
            container.appendChild(btn);
        });
        </script>
        """

        return render_page("Test Policies", content, "test")

    # ---- API Routes ----

    @app.route("/api/stats")
    def api_stats() -> Response:
        """Get audit statistics as JSON."""
        eng: PolicyEngine = app.extensions["agentshield_engine"]
        stats = eng.audit_logger.get_stats()
        stats["policies_count"] = len(eng.policy_set)
        stats["guards_count"] = len(eng.guards)
        return jsonify(stats)

    @app.route("/api/policies")
    def api_policies() -> Response:
        """Get all policies as JSON."""
        eng: PolicyEngine = app.extensions["agentshield_engine"]
        return jsonify({
            "name": eng.policy_set.name,
            "description": eng.policy_set.description,
            "policies": eng.get_policies_summary(),
        })

    @app.route("/api/guards")
    def api_guards() -> Response:
        """Get all guards as JSON."""
        eng: PolicyEngine = app.extensions["agentshield_engine"]
        return jsonify({
            "guards": eng.get_guards_summary(),
        })

    @app.route("/api/audit")
    def api_audit() -> Response:
        """Get audit log entries as JSON."""
        eng: PolicyEngine = app.extensions["agentshield_engine"]
        limit = flask_request.args.get("limit", 100, type=int)
        offset = flask_request.args.get("offset", 0, type=int)
        agent_id = flask_request.args.get("agent_id")
        decision = flask_request.args.get("decision")

        entries = eng.audit_logger.get_entries(
            limit=limit,
            offset=offset,
            agent_id=agent_id,
            decision=decision,
        )
        return jsonify({
            "entries": entries,
            "total": len(eng.audit_logger),
            "limit": limit,
            "offset": offset,
        })

    @app.route("/api/audit/export/json")
    def api_audit_export_json() -> Response:
        """Export all audit logs as JSON."""
        eng: PolicyEngine = app.extensions["agentshield_engine"]
        json_data = eng.audit_logger.export_json(pretty_print=True)
        return Response(json_data, mimetype="application/json")

    @app.route("/api/audit/export/csv")
    def api_audit_export_csv() -> Response:
        """Export all audit logs as CSV."""
        eng: PolicyEngine = app.extensions["agentshield_engine"]
        csv_data = eng.audit_logger.export_csv()
        return Response(csv_data, mimetype="text/csv")

    @app.route("/api/test", methods=["POST"])
    def api_test() -> Response:
        """Test a policy decision.

        Request body (JSON):
            action: The action to test.
            resource: The resource to test.
            agent_id: Optional agent identifier.

        Returns:
            JSON with the test result.
        """
        eng: PolicyEngine = app.extensions["agentshield_engine"]
        data = flask_request.get_json(force=True, silent=True) or {}

        action = data.get("action", "")
        resource = data.get("resource", "")
        agent_id = data.get("agent_id", "test_agent")

        if not action or not resource:
            return jsonify({"error": "action and resource are required"}), 400

        ctx = ExecutionContext(
            action=action,
            resource=resource,
            agent_id=agent_id,
        )

        try:
            allowed = eng.evaluate(action, resource, ctx)
            result = {
                "action": action,
                "resource": resource,
                "agent_id": agent_id,
                "decision": "allowed" if allowed else "denied",
                "effect": "allow" if allowed else "deny",
            }

            # Get matching policies for context
            matching = eng.policy_set.get_matching_policies(
                action, resource, ctx.get_evaluation_context()
            )
            result["matching_policies"] = [
                {
                    "name": p.name,
                    "effect": p.effect.value,
                    "priority": p.priority,
                }
                for p in matching
            ]

            return jsonify(result)

        except Exception as e:
            return jsonify({
                "action": action,
                "resource": resource,
                "agent_id": agent_id,
                "decision": "denied",
                "effect": "deny",
                "error": str(e),
            })

    @app.route("/api/templates")
    def api_templates() -> Response:
        """Get available built-in templates."""
        templates = {
            name: {
                "name": name,
                "description": getattr(BuiltinTemplates, name).__doc__ or "",
                "policy_count": len(getattr(BuiltinTemplates, name)().policies),
            }
            for name in ["strict", "balanced", "permissive", "owasp_top10"]
        }
        return jsonify({"templates": templates})

    @app.route("/api/templates/<name>/load", methods=["POST"])
    def api_load_template(name: str) -> Response:
        """Load a built-in template."""
        eng: PolicyEngine = app.extensions["agentshield_engine"]
        template_map = {
            "strict": BuiltinTemplates.strict,
            "balanced": BuiltinTemplates.balanced,
            "permissive": BuiltinTemplates.permissive,
            "owasp_top10": BuiltinTemplates.owasp_top10,
        }

        loader = template_map.get(name)
        if not loader:
            return jsonify({"error": f"Unknown template: {name}"}), 404

        try:
            eng.load_policy_set(loader())
            return jsonify({
                "message": f"Template '{name}' loaded successfully",
                "policy_count": len(eng.policy_set),
            })
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    return app


def run_dashboard(
    host: str = "0.0.0.0",
    port: int = 5000,
    debug: bool = False,
    engine: Optional[PolicyEngine] = None,
) -> None:
    """Run the AgentShield dashboard web server.

    Args:
        host: Host address to bind to.
        port: Port number to listen on.
        debug: Whether to run in debug mode.
        engine: Optional pre-configured PolicyEngine.
    """
    app = create_app(engine)
    app.run(host=host, port=port, debug=debug)


if __name__ == "__main__":
    run_dashboard()
