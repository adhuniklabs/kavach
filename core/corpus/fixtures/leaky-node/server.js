// Deliberately vulnerable fixture for KAVACH self-test. DO NOT DEPLOY.
const express = require("express");
const Anthropic = require("@anthropic-ai/sdk");
const Stripe = require("stripe");

// VULN: hardcoded provider keys committed to source
const anthropic = new Anthropic({ apiKey: "sk-ant-api03-abcDEF1234567890abcDEF1234567890abcd" });
const stripe = Stripe("sk_live_kavachFIXTUREtest123");
const DB = "postgres://admin:s3cr3tpass@db.internal:5432/app";

const app = express();
app.use(express.json());

// VULN: unauthenticated LLM proxy - "free chatbot for the world"
app.post("/api/chat", async (req, res) => {
  const out = await anthropic.messages.create({
    model: "claude-sonnet-5",
    max_tokens: 1024,
    messages: [{ role: "user", content: req.body.prompt }],
  });
  res.json(out);
});

// VULN: IDOR - no ownership check on the account id
app.get("/api/accounts/:id", (req, res) => {
  res.json(getAccount(req.params.id));
});

// VULN: client-trusted price
app.post("/api/checkout", async (req, res) => {
  await stripe.charges.create({ amount: req.body.price, currency: "usd" });
  res.json({ ok: true });
});

app.listen(3000);
