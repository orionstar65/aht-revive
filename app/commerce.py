import hashlib
import hmac
import json
import os
import time
import httpx

PLANS = {
    "assessment": {"name": "Device assessment", "amount": 3900, "description": "Written diagnostics and ownership path review"},
    "specialist": {"name": "Specialist recovery review", "amount": 9900, "description": "Priority technical review and guided support"},
}

async def start_checkout(*, order, user, case, request):
    key = os.getenv("STRIPE_SECRET_KEY")
    if not key:
        raise RuntimeError("Checkout is not configured. Add STRIPE_SECRET_KEY.")
    base_url = os.getenv("APP_URL", str(request.base_url).rstrip("/"))
    plan = PLANS[order.plan]
    data = {
        "mode": "payment",
        "payment_method_types[0]": "card",
        "customer_email": user.email,
        "client_reference_id": order.id,
        "success_url": f"{base_url}/checkout/success?session_id={{CHECKOUT_SESSION_ID}}",
        "cancel_url": f"{base_url}/cases/{case.id}?payment=cancelled",
        "line_items[0][quantity]": "1",
        "line_items[0][price_data][currency]": "usd",
        "line_items[0][price_data][unit_amount]": str(plan["amount"]),
        "line_items[0][price_data][product_data][name]": plan["name"],
        "metadata[order_id]": order.id,
        "metadata[case_id]": case.id,
    }
    async with httpx.AsyncClient(timeout=15) as client:
        response = await client.post("https://api.stripe.com/v1/checkout/sessions", data=data, auth=(key, ""))
    response.raise_for_status()
    payload = response.json()
    if not payload.get("url") or not payload.get("id"):
        raise RuntimeError("Stripe did not return a checkout session")
    return payload

def validate_webhook(payload: bytes, header: str) -> dict:
    secret = os.getenv("STRIPE_WEBHOOK_SECRET")
    if not secret:
        raise ValueError("Webhook secret not configured")
    pairs = dict(field.split("=", 1) for field in header.split(",") if "=" in field)
    timestamp = pairs.get("t", "")
    signatures = [field.split("=", 1)[1] for field in header.split(",") if field.startswith("v1=")]
    if not timestamp.isdigit() or abs(time.time()-int(timestamp)) > 300:
        raise ValueError("Invalid or expired webhook timestamp")
    signed = f"{timestamp}.".encode() + payload
    expected = hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()
    if not any(hmac.compare_digest(sig, expected) for sig in signatures):
        raise ValueError("Invalid webhook signature")
    return json.loads(payload)
