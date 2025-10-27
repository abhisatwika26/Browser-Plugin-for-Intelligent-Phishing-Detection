document.addEventListener("DOMContentLoaded", ()=>{
    chrome.runtime.sendMessage({ action:"getLatestAnalysis" }, analysis=>{
        if(!analysis) return;
        const banner = document.getElementById("riskBanner");
        const list = document.getElementById("reasons");
        if(!banner || !list) return;

        banner.className=`banner ${analysis.riskLevel.toLowerCase()}`;
        banner.textContent=`Risk: ${analysis.riskLevel}`;

        list.innerHTML="";
        analysis.results.forEach(r=>{
            const li=document.createElement("li");
            li.textContent=r;
            list.appendChild(li);
        });
    });
});
