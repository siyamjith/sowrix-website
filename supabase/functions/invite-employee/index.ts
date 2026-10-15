import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  const json = (body: unknown, status = 200) =>
    new Response(JSON.stringify(body), { status, headers: { ...cors, "Content-Type": "application/json" } });

  if (req.method !== "POST") return json({ error: "POST required" }, 405);

  const url = Deno.env.get("SUPABASE_URL");
  const anon = Deno.env.get("SUPABASE_ANON_KEY");
  const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  if (!url || !anon || !serviceKey) return json({ error: "Server environment is not configured." }, 500);

  const authHeader = req.headers.get("Authorization") || "";
  if (!authHeader.startsWith("Bearer ")) return json({ error: "Sign in as Admin or HR first." }, 401);

  const callerClient = createClient(url, anon, {
    global: { headers: { Authorization: authHeader } },
    auth: { persistSession: false, autoRefreshToken: false },
  });
  const { data: { user: caller }, error: callerError } = await callerClient.auth.getUser();
  if (callerError || !caller) return json({ error: "Invalid login session." }, 401);

  const adminClient = createClient(url, serviceKey, {
    auth: { persistSession: false, autoRefreshToken: false },
  });
  const { data: roleRow, error: roleError } = await adminClient
    .from("user_roles").select("role").eq("user_id", caller.id).maybeSingle();
  const callerRole = String(roleRow?.role || "").toLowerCase();
  if (roleError || !["admin", "hr"].includes(callerRole)) {
    return json({ error: "Only approved Admin/HR accounts can invite employees." }, 403);
  }

  let body: { email?: string; full_name?: string; employee_code?: string; department?: string; designation?: string };
  try { body = await req.json(); } catch { return json({ error: "Invalid JSON body." }, 400); }

  const email = String(body.email || "").trim().toLowerCase();
  const fullName = String(body.full_name || "").trim();
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !fullName) {
    return json({ error: "A valid employee email and full name are required." }, 400);
  }

  const redirectTo = Deno.env.get("EMPLOYEE_PASSWORD_REDIRECT_URL");
  if (!redirectTo) return json({ error: "Set EMPLOYEE_PASSWORD_REDIRECT_URL in Edge Function secrets." }, 500);

  // The Admin API sends the invite/password setup email. Service-role key stays server-side.
  const { data: invited, error: inviteError } = await adminClient.auth.admin.inviteUserByEmail(email, {
    redirectTo,
    data: { full_name: fullName, account_type: "employee" },
  });
  if (inviteError || !invited.user) {
    return json({ error: inviteError?.message || "Could not invite this employee." }, 400);
  }

  const { error: roleInsertError } = await adminClient.from("user_roles").upsert(
    { user_id: invited.user.id, role: "employee" }, { onConflict: "user_id" }
  );
  if (roleInsertError) {
    // Account was invited but permissions did not save; do not pretend setup succeeded.
    return json({ error: "Invite email was initiated, but employee role assignment failed. Admin must fix user_roles: " + roleInsertError.message }, 500);
  }

  const { error: profileError } = await adminClient.from("employee_profiles").upsert({
    user_id: invited.user.id,
    full_name: fullName,
    employee_code: body.employee_code?.trim() || null,
    department: body.department?.trim() || null,
    designation: body.designation?.trim() || null,
  }, { onConflict: "user_id" });

  if (profileError) {
    return json({ error: "Employee invited and role assigned, but profile save failed: " + profileError.message }, 500);
  }
  return json({ ok: true, message: "Employee invitation sent.", user_id: invited.user.id });
});
