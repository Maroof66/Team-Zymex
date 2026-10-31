import { createClient } from 'npm:@supabase/supabase-js@2';

const corsHeaders = {
  'Access-Control-Allow-Origin': 'https://maroof66.github.io',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Content-Type': 'application/json',
};
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: corsHeaders });
const enc = new TextEncoder();
function b64url(bytes: Uint8Array) {
  let binary = ''; for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}
function unb64url(s: string) {
  const base64 = s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - s.length % 4) % 4);
  const binary = atob(base64); return Uint8Array.from(binary, c => c.charCodeAt(0));
}
async function sign(payload: string, secret: string) {
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return b64url(new Uint8Array(await crypto.subtle.sign('HMAC', key, enc.encode(payload))));
}
async function validToken(token: string, secret: string) {
  const parts = token.split('.'); if (parts.length !== 2) return false;
  const expected = await sign(parts[0], secret);
  if (expected.length !== parts[1].length) return false;
  let diff = 0; for (let i = 0; i < expected.length; i++) diff |= expected.charCodeAt(i) ^ parts[1].charCodeAt(i);
  if (diff !== 0) return false;
  try { const payload = JSON.parse(new TextDecoder().decode(unb64url(parts[0]))); return payload.exp > Math.floor(Date.now() / 1000) && payload.role === 'admin'; } catch { return false; }
}
Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: corsHeaders });
  if (req.method !== 'POST') return json({ error: 'Method not allowed.' }, 405);
  const expectedOrigin = 'https://maroof66.github.io';
  if (req.headers.get('origin') && req.headers.get('origin') !== expectedOrigin) return json({ error: 'Origin not allowed.' }, 403);
  const adminPassword = Deno.env.get('ADMIN_DASHBOARD_PASSWORD');
  const tokenSecret = Deno.env.get('ADMIN_DASHBOARD_TOKEN_SECRET');
  if (!adminPassword || !tokenSecret) return json({ error: 'Admin function is missing its configured secrets.' }, 500);
  let body: Record<string, unknown>;
  try { body = await req.json(); } catch { return json({ error: 'Invalid JSON request.' }, 400); }
  if (body.action === 'login') {
    const supplied = typeof body.password === 'string' ? body.password : '';
    // Compare encoded values without exiting early.
    const a = enc.encode(supplied), b = enc.encode(adminPassword); let diff = a.length ^ b.length;
    for (let i = 0; i < Math.max(a.length, b.length); i++) diff |= (a[i] || 0) ^ (b[i] || 0);
    if (diff !== 0) { await new Promise(r => setTimeout(r, 700)); return json({ error: 'Incorrect password.' }, 401); }
    const payload = b64url(enc.encode(JSON.stringify({ role: 'admin', exp: Math.floor(Date.now() / 1000) + 8 * 60 * 60 })));
    return json({ token: payload + '.' + await sign(payload, tokenSecret) });
  }
  if (body.action !== 'registrations') return json({ error: 'Unknown action.' }, 400);
  const auth = req.headers.get('authorization') || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  if (!token || !(await validToken(token, tokenSecret))) return json({ error: 'Admin session expired. Enter the password again.' }, 401);
  const url = Deno.env.get('SUPABASE_URL');
  const serviceKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY');
  if (!url || !serviceKey) return json({ error: 'Supabase server configuration is missing.' }, 500);
  const supabase = createClient(url, serviceKey, { auth: { persistSession: false, autoRefreshToken: false } });
  const { data, error } = await supabase.from('Sport week registration').select('Name,Batch,"Name on Jersey","Jersey Number","Jersey Size","Major sports",created_at').order('created_at', { ascending: true });
  if (error) { console.error('Registration query failed:', error.message); return json({ error: 'Could not load registrations. Check the table name and service-role configuration.' }, 500); }
  return json({ rows: data || [] });
});
