let latestAnalysis = null;
let score = 0;

// ------------------- Utility Functions -------------------
function getDomain(email) {
    if (!email) return "";
    let parts = email.split("@");
    return parts.length > 1 ? parts[1].toLowerCase() : "";
}

function checkDisplayNameMismatch(fromHeader) {
    if (!fromHeader) return null;
    let match = fromHeader.match(/^(.*)<(.*)>$/);
    let displayName = "", email = "";
    if (match) {
        displayName = match[1].trim().toLowerCase();
        email = match[2].trim().toLowerCase();
    } else email = fromHeader.trim().toLowerCase();
    let emailDomain = getDomain(email);
    if (displayName && emailDomain && !emailDomain.includes(displayName)) {
        score += 30;
        return "Display name and domain mismatch";
    }
    return null;
}

function checkSuspiciousDomain(domain) {
    if (!domain) return null;
    if (/[0-9]/.test(domain)) { score += 20; return "Domain has numeric characters"; }
    if (/[^\x00-\x7F]/.test(domain)) { score += 20; return "Domain has non-ASCII chars"; }
    return null;
}

function checkUnsubscribe(headers) {
    if (!headers["list-unsubscribe"]) { score += 10; return "No unsubscribe header found"; }
    return null;
}

function checkReplyTo(headers) {
    if (!headers["reply-to"] || !headers["from"]) return null;
    let replyDomain = getDomain(headers["reply-to"]);
    let fromDomain = getDomain(headers["from"]);
    if (replyDomain && fromDomain && replyDomain !== fromDomain) { score += 25; return "Reply-To domain mismatch"; }
    return null;
}

function checkSuspiciousKeywords(subject, body) {
    const keywords = ["urgent","verify identity","password","login","unusual sign-in activity",
    "account suspended","action required","click here","confirm identity","security alert"];
    let found = [];
    if (subject) keywords.forEach(k => { if (subject.toLowerCase().includes(k)) found.push(k); });
    if (body) keywords.forEach(k => { if (body.toLowerCase().includes(k) && !found.includes(k)) found.push(k); });
    if (found.length > 0) { score += found.length*20; return `Suspicious keywords: ${found.join(", ")}`; }
    return null;
}

function checkAttachments(attachments) {
    if (!attachments || attachments.length===0) return null;
    const risky = [".exe",".bat",".scr",".vbs",".js",".docm",".xlsm",".pptm"];
    let bad = attachments.filter(att => risky.includes(att.filename.slice(att.filename.lastIndexOf('.')).toLowerCase()));
    if (bad.length>0) { score = 100; return `Malicious attachments: ${bad.map(a=>a.filename).join(", ")}`; }
    return null;
}

function checkLinkMismatches(bodyHtml) {
    if (!bodyHtml) return null;
    const parser = new DOMParser();
    const doc = parser.parseFromString(bodyHtml, 'text/html');
    const links = doc.querySelectorAll('a');
    let mismatches = [];
    links.forEach(link => {
        let href = link.href;
        let text = link.textContent.trim();
        if (href && text && !href.includes(text) && !text.includes(href)) mismatches.push(`${text} → ${href}`);
    });
    if (mismatches.length>0) { score += 40; return `Link text vs URL mismatch: ${mismatches.join(" | ")}`; }
    return null;
}

function checkAuthResults(headers) {
    if (!headers["authentication-results"]) return null;
    let auth = headers["authentication-results"].toLowerCase();
    if (auth.includes('dkim=fail') || auth.includes('spf=fail')) { score += 80; return "SPF/DKIM failed"; }
    return null;
}

// ------------------- Main Analysis -------------------
function runHeuristicChecks(emailData) {
    score = 0;
    let results = [];
    let isHighRisk = false;

    let headers = emailData.headers || {};
    let bodyText = emailData.bodyText || "";
    let bodyHtml = emailData.bodyHtml || "";
    let attachments = emailData.attachments || [];

    // High-risk checks
    [checkAuthResults(headers), checkAttachments(attachments),
     checkDisplayNameMismatch(headers["from"]), checkSuspiciousDomain(getDomain(headers["from"])),
     checkLinkMismatches(bodyHtml)].forEach(c => { if(c){results.push(c);isHighRisk=true;} });

    // Medium-risk checks
    [checkReplyTo(headers), checkUnsubscribe(headers), checkSuspiciousKeywords(headers["subject"], bodyText)]
    .forEach(c => { if(c) results.push(c); });

    let risk = "Low";
    if (isHighRisk) risk = "High";
    else if (results.length>0) risk = "Medium";

    latestAnalysis = { riskLevel: risk, score, results };
    console.log("Background analysis:", latestAnalysis);
    return latestAnalysis;
}

// ------------------- Message Handlers -------------------
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if(msg.action==="processFullEmail"){
        sendResponse(runHeuristicChecks(msg.emailData));
        return false; // synchronous
    }
    if(msg.action==="getLatestAnalysis"){
        sendResponse(latestAnalysis);
        return false;
    }
    if(msg.type==="GET_AUTH_TOKEN"){
        chrome.identity.getAuthToken({ interactive:true }, token => {
            if(chrome.runtime.lastError) sendResponse({error: chrome.runtime.lastError.message});
            else sendResponse({ token });
        });
        return true;
    }
});
