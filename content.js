let accessToken = null;
let lastMessageId = null;

// ------------------- Auth -------------------
async function getAuthToken(){
    return new Promise((resolve,reject)=>{
        chrome.runtime.sendMessage({type:"GET_AUTH_TOKEN"},res=>{
            if(res.error) reject(res.error);
            else resolve(res.token);
        });
    });
}

async function initAuth(){ if(!accessToken) accessToken=await getAuthToken(); }

// ------------------- Gmail Fetch -------------------
async function fetchLatestMessageId(){
    await initAuth();
    const res = await fetch('https://gmail.googleapis.com/gmail/v1/users/me/messages?labelIds=INBOX&maxResults=1',
        { headers: { Authorization:`Bearer ${accessToken}` } });
    const data = await res.json();
    if(!data.messages || !data.messages.length) return null;
    return data.messages[0].id;
}

async function fetchFullEmail(messageId){
    const res = await fetch(`https://gmail.googleapis.com/gmail/v1/users/me/messages/${messageId}?format=full`,
        { headers: { Authorization:`Bearer ${accessToken}` } });
    const data = await res.json();

    // parse payload
    const headers = {};
    data.payload.headers.forEach(h=>headers[h.name.toLowerCase()]=h.value);

    let bodyText="", bodyHtml="", attachments=[];
    function parseParts(parts){
        if(!parts) return;
        parts.forEach(p=>{
            if(p.mimeType==="text/plain" && p.body?.data) bodyText=atob(p.body.data.replace(/-/g,"+").replace(/_/g,"/"));
            else if(p.mimeType==="text/html" && p.body?.data) bodyHtml=atob(p.body.data.replace(/-/g,"+").replace(/_/g,"/"));
            else if(p.filename) attachments.push({ filename:p.filename, mimeType:p.mimeType, size:p.body?.size });
            if(p.parts) parseParts(p.parts);
        });
    }
    parseParts(data.payload.parts);

    // send to background for analysis
    chrome.runtime.sendMessage({ action:"processFullEmail", emailData:{ headers, bodyText, bodyHtml, attachments } }, res=>console.log("Analysis:",res));
}

// ------------------- Polling for new email -------------------
async function checkForNewEmail(){
    const messageId = await fetchLatestMessageId();
    if(!messageId || messageId===lastMessageId) return;
    lastMessageId = messageId;
    console.log("Fetching email ID:", messageId);
    fetchFullEmail(messageId);
}

setInterval(checkForNewEmail,5000); // or use MutationObserver
initAuth().catch(console.error);
