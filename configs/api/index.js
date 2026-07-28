const msal = require("@azure/msal-node");

function getRequiredEnv(name) {
    const value = process.env[name];

    if (!value || value.trim() === "") {
        throw new Error(`Missing required environment variable: ${name}`);
    }

    return value;
}

function normalizePrivateKey(privateKey) {
    return privateKey.replace(/\\n/g, "\n");
}

async function getPowerBiAccessToken() {
    const tenantId = getRequiredEnv("TENANT_ID");
    const clientId = getRequiredEnv("CLIENT_ID");
    const certThumbprint = getRequiredEnv("CERT_THUMBPRINT");
    const certPrivateKey = normalizePrivateKey(getRequiredEnv("CERT_PRIVATE_KEY"));
    const powerBiScope = process.env.POWERBI_SCOPE || "https://analysis.windows.net/powerbi/api/.default";

    const msalConfig = {
        auth: {
            clientId: clientId,
            authority: `https://login.microsoftonline.com/${tenantId}`,
            clientCertificate: {
                thumbprint: certThumbprint,
                privateKey: certPrivateKey
            }
        }
    };

    const confidentialClient = new msal.ConfidentialClientApplication(msalConfig);

    const result = await confidentialClient.acquireTokenByClientCredential({
        scopes: [powerBiScope]
    });

    if (!result || !result.accessToken) {
        throw new Error("Could not acquire Power BI access token.");
    }

    return result.accessToken;
}

async function powerBiFetch(url, accessToken, options = {}) {
    const response = await fetch(url, {
        ...options,
        headers: {
            Authorization: `Bearer ${accessToken}`,
            "Content-Type": "application/json",
            ...(options.headers || {})
        }
    });

    const text = await response.text();

    let body;
    try {
        body = text ? JSON.parse(text) : null;
    } catch {
        body = text;
    }

    if (!response.ok) {
        throw new Error(`Power BI API error ${response.status}: ${JSON.stringify(body)}`);
    }

    return body;
}

module.exports = async function (context, req) {
    try {
        if (req.method === "OPTIONS") {
            context.res = {
                status: 204,
                headers: {
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Methods": "POST, OPTIONS",
                    "Access-Control-Allow-Headers": "Content-Type"
                }
            };
            return;
        }

        const body = req.body || {};

        const name = body.name;
        const reportId = body.reportId;
        const groupId = body.groupId;
        const pageName = body.pageName;

        if (!reportId || !groupId) {
            context.res = {
                status: 400,
                body: {
                    error: "Missing reportId or groupId"
                }
            };
            return;
        }

        const accessToken = await getPowerBiAccessToken();

        const reportUrl =
            `https://api.powerbi.com/v1.0/myorg/groups/${encodeURIComponent(groupId)}` +
            `/reports/${encodeURIComponent(reportId)}`;

        const report = await powerBiFetch(reportUrl, accessToken);

        const generateTokenUrl =
            `https://api.powerbi.com/v1.0/myorg/groups/${encodeURIComponent(groupId)}` +
            `/reports/${encodeURIComponent(reportId)}/GenerateToken`;

        const tokenResponse = await powerBiFetch(generateTokenUrl, accessToken, {
            method: "POST",
            body: JSON.stringify({
                accessLevel: "View"
            })
        });

        context.res = {
            status: 200,
            headers: {
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": "*"
            },
            body: {
                name: name,
                reportId: reportId,
                groupId: groupId,
                pageName: pageName,
                embedUrl: report.embedUrl,
                accessToken: tokenResponse.token,
                tokenExpiration: tokenResponse.expiration,
                tokenType: "Embed",
                mode: "powerbi-embedded"
            }
        };
    } catch (error) {
        context.log.error(error);

        context.res = {
            status: 500,
            headers: {
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": "*"
            },
            body: {
                error: error.message
            }
        };
    }
};
