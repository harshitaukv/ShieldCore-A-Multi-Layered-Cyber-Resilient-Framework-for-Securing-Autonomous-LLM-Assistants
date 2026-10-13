// -----------------------------
// GLOBAL STATE
// -----------------------------
let selectedEmailText = "";
let currentEmailStatus = "";
let lastThreadId = "";
let analyzing = false;


// -----------------------------
// START
// -----------------------------
window.addEventListener("load", () => {
    console.log("Sentinel Started");

    addFloatingButton();
    detectOpenedEmail();
});


// -----------------------------
// FLOATING BUTTON
// -----------------------------
function addFloatingButton() {
    if (
        document.getElementById(
            "ai-float-btn"
        )
    ) {
        return;
    }

    let btn =
        document.createElement(
            "button"
        );

    btn.id = "ai-float-btn";
    btn.innerHTML = "✨";

    btn.style = `
        position:fixed;
        bottom:25px;
        right:25px;
        width:65px;
        height:65px;
        border-radius:50%;
        border:none;
        background:linear-gradient(
            135deg,
            #2563eb,
            #7c3aed
        );
        color:white;
        font-size:28px;
        cursor:pointer;
        z-index:999999;
        box-shadow:
            0 15px 35px rgba(
                37,99,235,0.35
            );
        transition:all 0.25s ease;
    `;

    btn.onmouseenter = () => {
        btn.style.transform =
            "scale(1.08)";
    };

    btn.onmouseleave = () => {
        btn.style.transform =
            "scale(1)";
    };

    btn.onclick =
        togglePanel;

    document.body.appendChild(
        btn
    );
}


// -----------------------------
// PANEL TOGGLE
// -----------------------------
function togglePanel() {
    let panel =
        document.getElementById(
            "sentinel-panel"
        );

    if (panel) {
        panel.remove();
    } else {
        createPanel();
    }
}


// -----------------------------
// CLEAN EMAIL TEXT
// -----------------------------
function cleanEmailText(text) {
    return text
        .replace(/unsubscribe/gi, "")
        .replace(/read more/gi, "")
        .replace(/comments?/gi, "")
        .replace(/upvotes?/gi, "")
        .replace(/hide.*$/gim, "")
        .trim();
}


// -----------------------------
// DETECT OPENED EMAIL
// -----------------------------
function detectOpenedEmail() {
    setInterval(() => {

        const currentThreadId =
            window.location.href;

        const emailBodies =
            document.querySelectorAll(
                "div.a3s.aiL, div.a3s"
            );

        if (!emailBodies.length) {
            return;
        }

        let fullText = "";

        emailBodies.forEach(body => {
            fullText +=
                "\n" +
                body.innerText;
        });

        const text =
            cleanEmailText(
                fullText
            );

        if (!text) {
            return;
        }

        if (text.length < 20) {
            return;
        }

        if (
            currentThreadId ===
            lastThreadId &&
            text ===
            selectedEmailText
        ) {
            return;
        }

        if (analyzing) {
            return;
        }

        analyzing = true;

        lastThreadId =
            currentThreadId;

        console.log(
            "New Email Opened"
        );

        setTimeout(() => {
            analyzeEmail(
                text,
                emailBodies[
                    emailBodies.length - 1
                ]
            );
        }, 1200);

    }, 1500);
}


// -----------------------------
// ANALYZE EMAIL
// -----------------------------
function analyzeEmail(
    text,
    emailBody
) {
    fetch(
        "https://sentinel-core-q5qw.onrender.com/analyze",
        {
            method: "POST",
            headers: {
                "Content-Type":
                    "application/json"
            },
            body: JSON.stringify({
                text: text
            })
        }
    )
    .then(res => res.json())
    .then(data => {

        console.log(
            "Detection:",
            data
        );

        analyzing = false;

        removeSafePopup();

        // BLOCKED MAIL
        if (
            data.status ===
            "BLOCKED"
        ) {
            currentEmailStatus =
                "BLOCKED";

            selectedEmailText =
                text;

            blockEmail(
                emailBody,
                data
            );

            return;
        }

        // SAFE / FLAGGED
        currentEmailStatus =
            data.status;

        selectedEmailText =
            text;

        showSafePopup(
            data.status
        );
    })
    .catch(err => {
        analyzing = false;

        console.log(
            "Analyze Error:",
            err
        );
    });
}


// -----------------------------
// BLOCK EMAIL
// -----------------------------
function blockEmail(
    emailBody,
    data
) {
    let container =
        emailBody.closest(
            "div[role='main']"
        );

    if (!container) {
        container = emailBody;
    }

    container.innerHTML = "";

    let blockUI =
        document.createElement(
            "div"
        );

    blockUI.style = `
        display:flex;
        align-items:center;
        justify-content:center;
        height:80vh;
    `;

    blockUI.innerHTML = `
        <div style="
            background:#1f2937;
            color:white;
            padding:25px;
            border-radius:12px;
            width:500px;
            text-align:center;
            box-shadow:0 0 20px rgba(0,0,0,0.5);
        ">
            <h2 style="
                color:red;
                margin-bottom:15px;
            ">
                🚫 Malicious Email Blocked
            </h2>

            <p>
                <b>Detected Type:</b>
                ${
                    data.types &&
                    data.types.length
                    ? data.types.join(", ")
                    : "Unknown Threat"
                }
            </p>

            <p style="
                margin-top:15px;
            ">
                This email contains suspicious
                instructions and has been blocked.
            </p>
        </div>
    `;

    container.appendChild(
        blockUI
    );
}


// -----------------------------
// SAFE POPUP
// -----------------------------
function showSafePopup(status) {
    removeSafePopup();

    let popup =
        document.createElement(
            "div"
        );

    popup.id =
        "safe-popup";

    let bg =
        status === "FLAGGED"
            ? "#f59e0b"
            : "#22c55e";

    let label =
        status === "FLAGGED"
            ? "⚠ Suspicious Email"
            : "✅ Safe Email";

    popup.style = `
        position:fixed;
        bottom:90px;
        right:20px;
        background:${bg};
        color:white;
        padding:10px 15px;
        border-radius:8px;
        z-index:9999;
        font-weight:bold;
    `;

    popup.innerText =
        label;

    document.body.appendChild(
        popup
    );

    setTimeout(() => {
        popup.remove();
    }, 3000);
}


// -----------------------------
// REMOVE SAFE POPUP
// -----------------------------
function removeSafePopup() {
    let popup =
        document.getElementById(
            "safe-popup"
        );

    if (popup) {
        popup.remove();
    }
}


// -----------------------------
// CREATE SMART PANEL UI
// -----------------------------
function createPanel() {

    let panel =
        document.createElement(
            "div"
        );

    panel.id =
        "sentinel-panel";

    panel.style = `
        position: fixed;
        top: 70px;
        right: 24px;
        width: 390px;
        height: 570px;
        background: #ffffff;
        border: 1.5px solid rgba(
        96,165,250,0.45
        );

        border-radius: 20px;
        z-index: 999999;
        font-family: Inter, system-ui, sans-serif;

        box-shadow:
    0 0 0 4px rgba(
        219,234,254,0.55
    ),
    0 12px 30px rgba(
        59,130,246,0.12
    ),
    0 24px 40px rgba(
        15,23,42,0.08
    );

        overflow: hidden;
        display: flex;
        flex-direction: column;
    `;

    panel.innerHTML = `

        <!-- HEADER -->
        <div style="
            height:78px;
            display:flex;
            align-items:center;
            justify-content:space-between;
            padding:0 24px;
            border-bottom:1px solid #f1f5f9;
        ">

            <div style="
                display:flex;
                align-items:center;
                gap:14px;
            ">

                <div style="
                    width:42px;
                    height:42px;
                    border-radius:12px;
                    background:#0f172a;
                    color:white;
                    display:flex;
                    align-items:center;
                    justify-content:center;
                    font-size:18px;
                    font-weight:700;
                ">
                    S
                </div>

                <div>
                    <div style="
                        font-size:18px;
                        font-weight:600;
                        color:#111827;
                    ">
                        SmartSummarizer✨
                    </div>

                    <div style="
                        font-size:12px;
                        color:#64748b;
                    ">
                        Secure AI Assistant
                    </div>
                </div>

            </div>

            <button
                id="close-panel"
                style="
                    border:none;
                    background:none;
                    font-size:22px;
                    cursor:pointer;
                    color:#64748b;
                    opacity:0.7;
                    transition:all 0.2s ease;
                "
            >
                ×
            </button>

        </div>


        <!-- BODY -->
        <div style="
            padding:22px;
            display:flex;
            flex-direction:column;
            gap:18px;
            flex:1;
        ">

            <!-- INPUT -->
            <div>

                <label style="
                    display:block;
                    margin-bottom:8px;
                    color:#475569;
                    font-size:13px;
                    font-weight:600;
                ">
                    Action
                </label>

                <input
                    id="cmd"
                    placeholder="summarize / simplify / reply"
                    style="
                        width:100%;
                        height:54px;
                        border-radius:14px;
                        border:1px solid #dbeafe;
                        background:#ffffff;
                        padding:0 16px;
                        font-size:14px;
                        outline:none;
                        box-sizing:border-box;
                        transition:all 0.2s ease;
                    "
                />

            </div>


            <!-- BUTTON -->
            <button
                id="runBtn"
                style="
                    width:100%;
                    height:54px;
                    border:none;
                    border-radius:14px;
                    background:#0f172a;
                    color:white;
                    font-size:15px;
                    font-weight:600;
                    cursor:pointer;
                    transition:all 0.2s ease;
                "
            >
                Execute
            </button>


            <!-- STATUS -->
            <div
                id="statusBox"
                style="
                    padding:16px;
                    border-radius:14px;
                    border:1px solid rgba(
                        59,130,246,0.20
                    );
                    background:#f8fbff;
                "
            >

                <div style="
                    font-size:14px;
                    font-weight:600;
                    color:#111827;
                    margin-bottom:6px;
                ">
                    Status
                </div>

                <div
                    id="statusText"
                    style="
                        font-size:13px;
                        color:#64748b;
                    "
                >
                    Ready for processing
                </div>

            </div>


            <!-- RESULT -->
            <div
                id="result"
                style="
                    flex:1;
                    padding:18px;
                    border-radius:16px;
                    background:#fafcff;
                    border:1px solid #dbeafe;
                    color:#111827;
                    font-size:14px;
                    line-height:1.7;
                    overflow-y:auto;
                    white-space:pre-wrap;
                    box-shadow:
                        inset 0 1px 3px rgba(
                            0,0,0,0.03
                        );
                "
            >
                No output yet.
            </div>

        </div>
    `;

    document.body.appendChild(
        panel
    );

    const closeBtn =
        document.getElementById(
            "close-panel"
        );

    const runBtn =
        document.getElementById(
            "runBtn"
        );

    const input =
        document.getElementById(
            "cmd"
        );

    // CLOSE BUTTON EFFECT
    closeBtn.onmouseenter = () => {
        closeBtn.style.opacity = "1";
    };

    closeBtn.onmouseleave = () => {
        closeBtn.style.opacity = "0.7";
    };

    closeBtn.onclick =
        () => panel.remove();

    // BUTTON HOVER
    runBtn.onmouseenter = () => {
        runBtn.style.transform =
            "translateY(-1px)";

        runBtn.style.boxShadow =
            "0 8px 18px rgba(15,23,42,0.12)";
    };

    runBtn.onmouseleave = () => {
        runBtn.style.transform =
            "translateY(0px)";

        runBtn.style.boxShadow =
            "none";
    };

    // INPUT FOCUS EFFECT
    input.onfocus = () => {
        input.style.border =
            "1px solid #60a5fa";

        input.style.boxShadow =
            "0 0 0 4px rgba(59,130,246,0.08)";
    };

    input.onblur = () => {
        input.style.border =
            "1px solid #dbeafe";

        input.style.boxShadow =
            "none";
    };

    runBtn.onclick =
        runTask;
}

// -----------------------------
// RUN TASK
// -----------------------------
function runTask() {

    let cmd =
        document
            .getElementById(
                "cmd"
            )
            .value
            .trim();

    let output =
        document.getElementById(
            "result"
        );

    let statusText =
        document.getElementById(
            "statusText"
        );

    if (
        !selectedEmailText
    ) {
        output.innerText =
            "Open an email first.";

        statusText.innerText =
            "No email selected";

        return;
    }

    if (
        currentEmailStatus ===
        "BLOCKED"
    ) {
        output.innerText =
            "Blocked mail cannot be processed.";

        statusText.innerText =
            "Blocked";

        return;
    }

    output.innerText =
        "Processing request...";

    statusText.innerText =
        "Processing...";

    fetch(
        "https://sentinel-core-q5qw.onrender.com/task",
        {
            method: "POST",
            headers: {
                "Content-Type":
                    "application/json"
            },
            body: JSON.stringify({
                command: cmd,
                email:
                    selectedEmailText
            })
        }
    )
    .then(res => res.json())
    .then(data => {

        output.innerText =
            data.result ||
            data.error;

        if (
            data.status ===
            "SAFE"
        ) {
            statusText.innerText =
                "Completed";
        } else {
            statusText.innerText =
                "Blocked";
        }
    })
    .catch(err => {

        console.log(
            "Task Error:",
            err
        );

        output.innerText =
            "Task failed.";

        statusText.innerText =
            "Failed";
    });
}