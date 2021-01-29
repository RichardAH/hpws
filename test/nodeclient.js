const WebSocket = require("ws");

const server = "wss://localhost:9001";
const agent = "nodeclient";
const totalCases = 10;
let caseId = 1;

function runNextCase() {
    const ws = new WebSocket(`${server}/runCase?case=${caseId}&agent=${agent}`, { rejectUnauthorized: false });

    ws.addEventListener("open", () => {
        console.log("Connected (testCase: " + caseId + ")");
    });

    ws.addEventListener("message", (msg) => {
        ws.send(msg.data);
    });

    ws.addEventListener("error", (err) => {
        console.log(err.message);
    });

    ws.addEventListener("close", () => {
        console.log("Connection closed.");
        caseId++;
        if (caseId <= totalCases)
            runNextCase();
        else
            updateReports();
    });
}

function updateReports() {
    const ws = new WebSocket(`${server}/updateReports?agent=${agent}`, { rejectUnauthorized: false });

    ws.addEventListener("open", () => {
        console.log("Updating reports...");
    });

    ws.addEventListener("error", (err) => {
        console.log(err.message);
    });

    ws.addEventListener("close", () => {
        console.log("Reports updated.");
    });
}

runNextCase();
