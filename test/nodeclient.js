const WebSocket = require("ws");

const totalCases = 10;
let caseId = 1;

function runNextCase() {
    const ws = new WebSocket(`wss://localhost:9001/runCase?case=${caseId}&agent=nodeclient`, { rejectUnauthorized: false });

    ws.addEventListener("open", () => {
        console.log("Connected (testCase: " + caseId + ")");
    });

    ws.addEventListener("message", (msg) => {
        ws.send(msg.data);
    });

    ws.addEventListener("close", () => {
        console.log("Connection closed.");
        caseId++;
        if (caseId <= totalCases) {
            runNextCase();
        }
    });
}

runNextCase();
