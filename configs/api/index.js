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

function parseJsonEnv(name, fallback = null) {
    const value = process.env[name];

    if (!value || value.trim() === "") {
        return fallback;
    }

    try {
        return JSON.parse(value);
    } catch (error) {
        throw new Error(`Environment variable ${name} is not valid JSON: ${error.message}`);
    }
}

function normalizeIp(ip) {
    if (!ip) return "";

    let value = String(ip).trim();

    if (value.startsWith("::ffff:")) {
        value = value.substring(7);
    }

    return value;
}

function getClientIp(req) {
    const headers = req.headers || {};

    const xForwardedFor =
        headers["x-forwarded-for"] ||
        headers["X-Forwarded-For"];

    if (xForwardedFor) {
        return normalizeIp(String(xForwardedFor).split(",")[0]);
    }

    const xAzureClientIp =
        headers["x-azure-clientip"] ||
        headers["X-Azure-ClientIP"];

    if (xAzureClientIp) {
        return normalizeIp(xAzureClientIp);
    }

    const clientIp =
        headers["x-client-ip"] ||
        headers["X-Client-IP"] ||
        headers["client-ip"] ||
        headers["Client-IP"];

    if (clientIp) {
        return normalizeIp(clientIp);
    }

    return "";
}

function isIpAllowed(clientIp, allowedIps) {
    if (!Array.isArray(allowedIps) || allowedIps.length === 0) {
        return false;
    }

    if (allowedIps.includes("*")) {
        return true;
    }

    return allowedIps
        .map(normalizeIp)
        .includes(normalizeIp(clientIp));
}

function isReportAllowed(siteConfig, groupId, reportId) {
    if (!siteConfig) {
        return false;
    }

    const allowedReports = siteConfig.allowedReports;

    // Midlertidig praktisk model:
    // Tom allowedReports betyder: tillad rapporter efter device/key/IP-check.
    // Senere kan vi gøre den strict og liste hver rapport eksplicit.
    if (!Array.isArray(allowedReports) || allowedReports.length === 0) {
        return true;
    }

    return allowedReports.some(report =>
        String(report.groupId).toLowerCase() === String(groupId).toLowerCase() &&
        String(report.reportId).toLowerCase() === String(reportId).toLowerCase()
    );
}

function validateDeviceAccess(req, body) {
    const accessConfig = parseJsonEnv("DEVICE_ACCESS_CONFIG", null);

    if (!accessConfig) {
        throw new Error("Missing DEVICE_ACCESS_CONFIG environment variable.");
    }

    const site = body.site;
    const device = body.device;
    const key = body.key;
    const groupId = body.groupId;
    const reportId = body.reportId;

    if (!site || !device || !key) {
        return {
            ok: false,
            status: 403,
            error: "Missing site, device or key."
        };
    }

    const deviceConfig = accessConfig.devices && accessConfig.devices[device];

    if (!deviceConfig) {
        return {
            ok: false,
            status: 403,
            error: "Unknown device."
        };
    }

    if (String(deviceConfig.key) !== String(key)) {
        return {
            ok: false,
            status: 403,
            error: "Invalid device key."
        };
    }

    if (String(deviceConfig.site) !== String(site)) {
        return {
            ok: false,
            status: 403,
            error: "Device is not allowed for this site."
        };
    }

    const clientIp = getClientIp(req);

    if (!isIpAllowed(clientIp, deviceConfig.allowedIps)) {
        return {
            ok: false,
            status: 403,
            error: `IP is not allowed for this device. Detected IP: ${clientIp || "unknown"}`
        };
    }

    const siteConfig = accessConfig.sites && accessConfig.sites[site];

    if (!isReportAllowed(siteConfig, groupId, reportId)) {
        return {
            ok: false,
            status: 403,
            error: "Report is not allowed for this site."
        };
    }

    return {
        ok: true,
        site,
        device,
        clientIp
    };
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

async function powerBiFetch(label, url, accessToken, options = {}) {
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
        throw new Error(`${label} failed. Power BI API error ${response.status} ${response.statusText}: ${JSON.stringify(body)}`);
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
                headers: {
                    "Content-Type": "application/json",
                    "Access-Control-Allow-Origin": "*"
                },
                body: {
                    error: "Missing reportId or groupId"
                }
            };
            return;
        }

        const access = validateDeviceAccess(req, body);

        if (!access.ok) {
            context.res = {
                status: access.status || 403,
                headers: {
                    "Content-Type": "application/json",
                    "Access-Control-Allow-Origin": "*"
                },
                body: {
                    error: access.error
                }
            };
            return;
        }

        context.log(`Access granted. Site=${access.site}, Device=${access.device}, IP=${access.clientIp}`);

        const accessToken = await getPowerBiAccessToken();

        const reportUrl =
            `https://api.powerbi.com/v1.0/myorg/groups/${encodeURIComponent(groupId)}` +
            `/reports/${encodeURIComponent(reportId)}`;

        const report = await powerBiFetch("Get report", reportUrl, accessToken);

        const generateTokenUrl =
            `https://api.powerbi.com/v1.0/myorg/groups/${encodeURIComponent(groupId)}` +
            `/reports/${encodeURIComponent(reportId)}/GenerateToken`;

        const tokenResponse = await powerBiFetch("Generate embed token", generateTokenUrl, accessToken, {
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
