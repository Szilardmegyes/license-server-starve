export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: cors() });
    }

    if (url.pathname === "/") {
      return new Response("License server running", { headers: cors() });
    }

    if (request.method === "POST" && url.pathname === "/api/check") {
      const body = await request.json();
      const { key, clientId, hw } = body;

      if (!key) {
        return json({ valid: false, error: "missing_key" });
      }

      let record = await env.DB.get(key, { type: "json" });

      if (!record) {
        return json({ valid: false, error: "invalid_key" });
      }

      // active check
      if (record.active && record.clientId && record.clientId !== clientId) {
        return json({ valid: false, error: "key_in_use" });
      }

      const sessionToken = crypto.randomUUID();

      record.active = true;
      record.clientId = clientId;
      record.hw = hw;
      record.sessionToken = sessionToken;
      record.expiresAt = Date.now() + 60000;

      await env.DB.put(key, JSON.stringify(record));

      return json({
        valid: true,
        sessionToken
      });
    }

    if (request.method === "POST" && url.pathname === "/api/heartbeat") {
      const body = await request.json();
      const { sessionToken, clientId } = body;

      const list = await env.DB.list();
      for (const k of list.keys) {
        const record = await env.DB.get(k.name, { type: "json" });

        if (record?.sessionToken === sessionToken) {

          if (record.clientId !== clientId) {
            return json({ valid: false });
          }

          record.expiresAt = Date.now() + 60000;
          await env.DB.put(k.name, JSON.stringify(record));

          return json({ valid: true });
        }
      }

      return json({ valid: false });
    }

    if (request.method === "POST" && url.pathname === "/api/release") {
      const body = await request.json();
      const { sessionToken } = body;

      const list = await env.DB.list();
      for (const k of list.keys) {
        const record = await env.DB.get(k.name, { type: "json" });

        if (record?.sessionToken === sessionToken) {
          record.active = false;
          record.clientId = null;
          record.sessionToken = null;
          await env.DB.put(k.name, JSON.stringify(record));
        }
      }

      return json({ ok: true });
    }

    return new Response("Not found", { status: 404 });
  }
};

function json(data) {
  return new Response(JSON.stringify(data), {
    headers: {
      "Content-Type": "application/json",
      ...cors()
    }
  });
}

function cors() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type"
  };
}
