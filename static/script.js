// Labels that mean "safe". Anything else is treated as phishing, so an
// unexpected label never shows up as safe by mistake.
const SAFE_LABELS = ["safe", "legitimate", "benign", "label_0", "0"];
 
const form = document.getElementById("urlForm");
const input = document.getElementById("url");
const submitBtn = document.getElementById("submit");
const result = document.getElementById("result");
const anatomy = document.getElementById("anatomy");
const prediction = document.getElementById("prediction");
const confidence = document.getElementById("confidence");
const meterFill = document.getElementById("meterFill");
const historyWrap = document.getElementById("historyWrap");
const historyList = document.getElementById("history");
 
const history = [];
 
function isDanger(label) {
    return !SAFE_LABELS.includes(String(label).toLowerCase());
}
 
// Split the URL into scheme / host / rest so the host can be highlighted.
function renderAnatomy(raw) {
    anatomy.textContent = "";
 
    const match = raw.match(/^([a-z][a-z0-9+.-]*:\/\/)?([^\/?#]*)(.*)$/i);
    const parts = [
        ["", match ? match[1] || "" : ""],
        ["host", match ? match[2] : raw],
        ["", match ? match[3] : ""],
    ];
 
    for (const [cls, text] of parts) {
        if (!text) continue;
        const span = document.createElement("span");
        if (cls) span.className = cls;
        span.textContent = text;
        anatomy.appendChild(span);
    }
}
 
function show(state, { url, title, detail, percent }) {
    result.hidden = false;
    result.dataset.state = state;
    renderAnatomy(url);
    prediction.textContent = title;
    confidence.textContent = detail;
    meterFill.style.width = percent ? percent + "%" : "0";
}
 
function addHistory(url, danger) {
    history.unshift({ url, danger });
    if (history.length > 6) history.pop();
 
    historyList.textContent = "";
 
    for (const item of history) {
        const li = document.createElement("li");
        const btn = document.createElement("button");
        btn.type = "button";
 
        const urlSpan = document.createElement("span");
        urlSpan.className = "url";
        urlSpan.textContent = item.url;
 
        const tag = document.createElement("span");
        tag.className = "tag " + (item.danger ? "danger" : "safe");
        tag.textContent = item.danger ? "Phishing" : "Safe";
 
        btn.append(urlSpan, tag);
        btn.addEventListener("click", () => {
            input.value = item.url;
            form.requestSubmit();
        });
 
        li.appendChild(btn);
        historyList.appendChild(li);
    }
 
    historyWrap.hidden = false;
}
 
form.addEventListener("submit", async function (event) {
    event.preventDefault();
 
    const url = input.value.trim();
    if (!url) {
        show("error", {
            url: "",
            title: "Enter a link first",
            detail: "Paste the full URL you want to check.",
        });
        return;
    }
 
    submitBtn.disabled = true;
    submitBtn.textContent = "Checking...";
 
    try {
        const response = await fetch("/predict", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url: url }),
        });
 
        const data = await response.json();
 
        if (!response.ok) {
            show("error", {
                url,
                title: "Couldn't check that link",
                detail: data.error || "The server returned an error.",
            });
            return;
        }
 
        const danger = isDanger(data.prediction);
        const percent = (data.confidence * 100).toFixed(1);
 
        show(danger ? "danger" : "safe", {
            url,
            title: danger ? "Looks like phishing" : "Looks safe",
            detail: percent + "% confidence" +
                (data.reasons && data.reasons.length
                    ? ". Flagged because " + data.reasons.join("; ") + "."
                    : ""),
            percent: percent,
        });
 
        addHistory(url, danger);
    } catch (err) {
        show("error", {
            url,
            title: "Couldn't reach the server",
            detail: "Check that the Flask app is still running, then try again.",
        });
    } finally {
        submitBtn.disabled = false;
        submitBtn.textContent = "Check link";
    }
});
 

