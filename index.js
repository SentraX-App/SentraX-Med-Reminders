// Patient-facing "time for your medication" push -- runs as a Cloudflare
// Worker Cron Trigger, separate from (and not calling) the existing
// sentrax-alert-checker Worker that alerts CAREGIVERS once a dose is 10
// minutes overdue. This one warns the PATIENT right when a dose becomes
// due, giving a real window to act before that caregiver alert ever fires.
//
// Written against the Workers runtime specifically (fetch + Web Crypto),
// not Node's firebase-admin -- firebase-admin needs Node-only networking
// (gRPC) that Workers doesn't provide, so this talks to Firestore directly
// over its REST API instead, authenticating with a hand-signed Google
// service-account JWT via crypto.subtle. @block65/webcrypto-web-push (the
// library already sitting in this project's package.json) was built for
// exactly this kind of edge runtime, which is why it was chosen originally.
//
// HONESTY NOTE, worth keeping in mind for app-store review copy: no push
// system on any platform -- this one included -- can promise a notification
// arrives at the exact instant it's due. The OS can still delay it (Doze/
// battery optimization on Android, Focus/Do Not Disturb or a killed Safari
// process on iOS), and on iOS this ONLY works at all if the patient added
// Sentra-X to their Home Screen and granted notification permission --
// push does not reach an ordinary Safari tab. "Reminds the patient so a
// caregiver alert is rarely needed" is accurate; "guarantees"/"always" is
// not, for any reminder app on any platform.

import { ApplicationServer, PushSubscriber } from '@block65/webcrypto-web-push';

export default {
  async scheduled(event, env, ctx) {
    ctx.waitUntil(run(env));
  },
  // Lets you trigger a run manually by visiting the Worker's URL, to test
  // before trusting the Cron Trigger -- harmless to leave in production.
  async fetch(request, env, ctx) {
    await run(env);
    return new Response('Reminder check complete.');
  }
};

async function run(env) {
  const serviceAccount = JSON.parse(env.FIREBASE_SERVICE_ACCOUNT);
  const accessToken = await getGoogleAccessToken(serviceAccount);
  const projectId = serviceAccount.project_id;
  const server = new ApplicationServer({
    contactInformation: env.VAPID_SUBJECT,
    vapidKeys: { publicKey: env.VAPID_PUBLIC_KEY, privateKey: env.VAPID_PRIVATE_KEY }
  });

  const users = await listUsers(accessToken, projectId);
  console.log('Scanning', users.length, 'users for due medication reminders...');
  for (const doc of users) {
    try {
      await checkUser(doc, accessToken, server);
    } catch (err) {
      console.error('Error checking user', doc.name, err);
    }
  }
}

async function checkUser(doc, accessToken, server) {
  const data = decodeFields(doc.fields || {});
  if (!data.pushSubscription) return; // nothing to push to

  const today = localDateStrNigeria();
  const nowMin = nowMinutesNigeria();
  const meds = data.meds || [];
  const medLogs = data.medLogs || {};
  const todayLog = medLogs[today] || {};
  const remindersSent = data.medRemindersSent || {};

  const due = meds.filter(function (m) {
    if (todayLog[m.id]) return false;
    if (m.startDate && m.durationDays) {
      const endDate = new Date(m.startDate);
      endDate.setDate(endDate.getDate() + m.durationDays);
      if (new Date() > endDate) return false;
    } else if (!m.durationDays) {
      const created = m.createdAt || parseInt(m.id, 10) || 0;
      if (created && (Date.now() - created) > 60 * 60 * 1000) return false;
    }
    return timeToMinutes(m.time) <= nowMin;
  });
  if (due.length === 0) return;

  // Re-fire only when the SET of due meds changes -- same dedup the
  // client's own checkDueMeds() in script.js uses, so a second medication
  // due later the same day still gets its own notification.
  const dueKey = today + ':' + due.map(function (m) { return m.id; }).sort().join(',');
  if (remindersSent[dueKey]) return;

  const names = due.map(function (m) { return m.name; }).join(', ');
  const ok = await sendPush(server, data.pushSubscription, 'Sentra-X reminder', 'Time for: ' + names + '. Mark it taken in the app.');
  if (ok) {
    remindersSent[dueKey] = true;
    await patchUserField(accessToken, doc.name, 'medRemindersSent', remindersSent);
  }
}

async function sendPush(server, subscriptionJson, title, body) {
  try {
    const subscriber = new PushSubscriber(subscriptionJson);
    await server.sendMessage(subscriber, JSON.stringify({ title: title, body: body }));
    return true;
  } catch (err) {
    // A 404/410 here means the subscription is dead (uninstalled, cleared
    // data, etc.) -- not a transient failure, so this doesn't retry it.
    console.error('Push send failed:', err && err.message);
    return false;
  }
}

// ---------------------------------------------------------------------
// Nigeria-time helpers -- same approach as check-alerts.js, intentionally
// duplicated (not imported) so this Worker deploys and rolls back on its
// own, independent of that file.
// ---------------------------------------------------------------------
const NIGERIA_UTC_OFFSET_MS = 60 * 60 * 1000;
function localDateStrNigeria() {
  const nigeriaTime = new Date(Date.now() + NIGERIA_UTC_OFFSET_MS);
  return nigeriaTime.toISOString().split('T')[0];
}
function nowMinutesNigeria() {
  const now = new Date();
  return ((now.getUTCHours() * 60 + now.getUTCMinutes()) + 60) % 1440;
}
function timeToMinutes(t) {
  const parts = t.split(':');
  return parseInt(parts[0], 10) * 60 + parseInt(parts[1], 10);
}

// ---------------------------------------------------------------------
// Minimal Google OAuth2 (service-account JWT bearer flow) + Firestore
// REST client, built on fetch + Web Crypto only -- no Node APIs, so this
// runs natively on Workers.
// ---------------------------------------------------------------------
async function getGoogleAccessToken(serviceAccount) {
  const header = { alg: 'RS256', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);
  const claim = {
    iss: serviceAccount.client_email,
    scope: 'https://www.googleapis.com/auth/datastore',
    aud: 'https://oauth2.googleapis.com/token',
    exp: now + 3600,
    iat: now
  };
  const unsigned = base64UrlJson(header) + '.' + base64UrlJson(claim);
  const key = await importPrivateKey(serviceAccount.private_key);
  const sigBuf = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, new TextEncoder().encode(unsigned));
  const jwt = unsigned + '.' + arrayBufferToBase64Url(sigBuf);

  const resp = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: 'grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=' + jwt
  });
  const data = await resp.json();
  if (!data.access_token) throw new Error('Failed to get Google access token: ' + JSON.stringify(data));
  return data.access_token;
}

async function importPrivateKey(pem) {
  const pemBody = pem.replace(/-----BEGIN PRIVATE KEY-----/, '').replace(/-----END PRIVATE KEY-----/, '').replace(/\s/g, '');
  const binaryDer = base64ToArrayBuffer(pemBody);
  return crypto.subtle.importKey('pkcs8', binaryDer, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']);
}

async function listUsers(accessToken, projectId) {
  let docs = [];
  let pageToken = null;
  do {
    const url = 'https://firestore.googleapis.com/v1/projects/' + projectId + '/databases/(default)/documents/users?pageSize=300' + (pageToken ? '&pageToken=' + encodeURIComponent(pageToken) : '');
    const resp = await fetch(url, { headers: { Authorization: 'Bearer ' + accessToken } });
    const data = await resp.json();
    if (data.documents) docs = docs.concat(data.documents);
    pageToken = data.nextPageToken || null;
  } while (pageToken);
  return docs;
}

async function patchUserField(accessToken, docName, fieldName, value) {
  // docName is the full resource path Firestore already gave us, e.g.
  // "projects/x/databases/(default)/documents/users/UID" -- safe to PATCH
  // directly rather than rebuilding it.
  const url = 'https://firestore.googleapis.com/v1/' + docName + '?updateMask.fieldPaths=' + encodeURIComponent(fieldName);
  await fetch(url, {
    method: 'PATCH',
    headers: { Authorization: 'Bearer ' + accessToken, 'Content-Type': 'application/json' },
    body: JSON.stringify({ fields: { [fieldName]: encodeValue(value) } })
  });
}

// ---- Firestore REST <-> plain JS value conversion ----
function decodeValue(v) {
  if (v.stringValue !== undefined) return v.stringValue;
  if (v.integerValue !== undefined) return parseInt(v.integerValue, 10);
  if (v.doubleValue !== undefined) return v.doubleValue;
  if (v.booleanValue !== undefined) return v.booleanValue;
  if (v.nullValue !== undefined) return null;
  if (v.timestampValue !== undefined) return v.timestampValue;
  if (v.arrayValue !== undefined) return (v.arrayValue.values || []).map(decodeValue);
  if (v.mapValue !== undefined) return decodeFields(v.mapValue.fields || {});
  return null;
}
function decodeFields(fields) {
  const out = {};
  for (const k in fields) out[k] = decodeValue(fields[k]);
  return out;
}
function encodeValue(v) {
  if (v === null || v === undefined) return { nullValue: null };
  if (typeof v === 'string') return { stringValue: v };
  if (typeof v === 'boolean') return { booleanValue: v };
  if (typeof v === 'number') return Number.isInteger(v) ? { integerValue: String(v) } : { doubleValue: v };
  if (Array.isArray(v)) return { arrayValue: { values: v.map(encodeValue) } };
  return { mapValue: { fields: encodeFields(v) } };
}
function encodeFields(obj) {
  const out = {};
  for (const k in obj) out[k] = encodeValue(obj[k]);
  return out;
}

// ---- base64url helpers ----
function base64UrlJson(obj) {
  return btoa(JSON.stringify(obj)).replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
}
function base64ToArrayBuffer(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}
function arrayBufferToBase64Url(buf) {
  const bytes = new Uint8Array(buf);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
}
