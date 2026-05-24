# appear

[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Know when ChatGPT, Perplexity, Claude, or Gemini sends you a customer — and how much they're worth.

## How it works

- Drop a 2 KB script on your site. It detects AI referrers (referrer URL + `utm_source`) and sends a visit event to your server with a session ID.
- On checkout, pass that session ID in Stripe or LemonSqueezy metadata.
- When the payment webhook arrives, appear matches it to the visit and records the attribution.

## Quick start

**1. Add the snippet to your site**

```html
<script src="https://cdn.jsdelivr.net/gh/yigitmeteozcan/appear@main/src/appear.js"></script>
<script>
  Appear.init({
    webhookUrl: 'https://your-appear-server.com/appear/event',
  });
</script>
```

**2. Pass the session ID at checkout**

```js
const events = Appear.getEvents();
const sessionId = events[0]?.session_id;

// Stripe: put it in metadata
await stripe.checkout.sessions.create({
  metadata: { appear_session_id: sessionId },
  // ...
});
```

**3. Run the server**

```bash
cp .env.example .env   # fill in API_KEY, STRIPE_WEBHOOK_SECRET, etc.
npm install
npm start
```

**4. Point your webhooks at the server**

- Stripe: `POST https://your-appear-server.com/stripe/webhook`
- LemonSqueezy: `POST https://your-appear-server.com/lemonsqueezy/webhook`

**5. Query attribution stats**

```bash
curl -H "x-api-key: YOUR_API_KEY" https://your-appear-server.com/appear/stats
```

---

## Configuration

### `Appear.init(config)` — browser snippet

| Option | Type | Default | Description |
|---|---|---|---|
| `webhookUrl` | `string` | required | Your appear server URL. Must be `https`. |
| `onDetect` | `function` | — | Called with the detection object when an AI visit is found. |
| `debug` | `boolean` | `false` | Log detections to the browser console. |
| `sendUserAgent` | `boolean` | `false` | Include `navigator.userAgent` in the payload. Off by default for privacy. |
| `maxStoredEvents` | `number` | `50` | Max events kept in `sessionStorage`. |

### Server environment variables

| Variable | Required | Description |
|---|---|---|
| `API_KEY` | yes | Secret key for `/appear/stats`. Generate with `openssl rand -hex 32`. |
| `STRIPE_SECRET_KEY` | Stripe only | Your Stripe secret key. |
| `STRIPE_WEBHOOK_SECRET` | Stripe only | Webhook signing secret from Stripe Dashboard. |
| `LEMONSQUEEZY_WEBHOOK_SECRET` | LS only | Signing secret from LemonSqueezy Dashboard. |
| `ALLOWED_ORIGINS` | yes | Comma-separated list of CORS origins (your site's domain). |
| `PORT` | no | Server port. Default `3000`. |
| `DATABASE_URL` | no | Path to SQLite file (e.g. `./appear.db`). Omit for in-memory only. |

---

## Detected AI engines

| Engine | Referrer domains | `utm_source` values |
|---|---|---|
| ChatGPT | `chatgpt.com`, `chat.openai.com` | `chatgpt`, `chat.openai` |
| Perplexity | `perplexity.ai` | `perplexity` |
| Claude | `claude.ai` | `claude` |
| Gemini | `gemini.google.com`, `bard.google.com` | `gemini`, `bard` |
| Copilot | `copilot.microsoft.com`, `bing.com/chat` | `copilot`, `bing` |
| You.com | `you.com` | `you` |
| Phind | `phind.com` | `phind` |
| Poe | `poe.com` | `poe` |

---

## Stripe setup

1. In the [Stripe Dashboard](https://dashboard.stripe.com/webhooks), add a webhook endpoint pointing to `https://your-appear-server.com/stripe/webhook`.
2. Select events: `checkout.session.completed`, `payment_intent.succeeded`.
3. Copy the signing secret into `STRIPE_WEBHOOK_SECRET` in your `.env`.
4. When creating a Checkout Session, include the appear session ID in metadata:

```js
await stripe.checkout.sessions.create({
  metadata: { appear_session_id: req.body.appear_session_id },
  // ...
});
```

## LemonSqueezy setup

1. In LemonSqueezy → Settings → Webhooks, add your endpoint: `https://your-appear-server.com/lemonsqueezy/webhook`.
2. Select event: `order_created`.
3. Copy the signing secret into `LEMONSQUEEZY_WEBHOOK_SECRET`.
4. Pass the session ID through the checkout URL:

```
https://yourstore.lemonsqueezy.com/checkout/buy/VARIANT_ID
  ?checkout[custom][appear_session_id]=SESSION_ID
```

---

## Security

| What | How |
|---|---|
| API key auth | Constant-time comparison (`crypto.timingSafeEqual`) prevents timing attacks |
| Rate limiting | 60 req/min on event ingestion, 20/min on webhooks, 30/min on stats |
| Input validation | `express-validator` rejects unknown fields, enforces types and max lengths |
| Webhook signatures | Stripe: `stripe.webhooks.constructEvent`; LemonSqueezy: HMAC-SHA256 |
| HTTP headers | `helmet` sets `Content-Security-Policy`, `X-Frame-Options`, etc. |
| CORS | Allowlist-only, default deny |
| Body size limits | JSON: 10 KB; raw (Stripe): 1 MB |
| Error messages | Generic errors to clients; full errors logged server-side only |
| Privacy | User agent not collected by default; `sessionStorage` (not `localStorage`) |
| No eval | The browser snippet contains no `eval`, `Function()`, or `innerHTML` |

---

## Deployment

### Railway

```bash
# Install Railway CLI, then:
railway login
railway init
railway up
```

Set environment variables in the Railway dashboard under Variables. Railway auto-assigns a public URL — point your Stripe/LemonSqueezy webhooks there.

For SQLite persistence, add a volume mount and set `DATABASE_URL=/data/appear.db`.

### Render

1. Create a new **Web Service** in the Render dashboard.
2. Connect your GitHub repo.
3. Set **Build Command**: `npm install`
4. Set **Start Command**: `npm start`
5. Add all environment variables under **Environment**.

For persistence, add a Render **Disk** mounted at `/data` and set `DATABASE_URL=/data/appear.db`.

---

## Running tests

```bash
npm test
```

Uses Node's built-in test runner (`node:test`). No extra dependencies required.

---

## License

MIT
