const crypto = require("crypto");
const msal = require("@azure/msal-node");

//////////////////////////////////////////////////////
// ENVIRONMENT VARIABLES
//////////////////////////////////////////////////////

function getRequiredEnv(name) {
    const value = process.env[name];

    if (!value || value.trim() === "") {
        throw new Error(
            `Missing required environment variable: ${name}`
        );
    }

    return value;
}

function parseJsonEnv(name, fallback = null) {
    const value = process.env[name];

    if (!value || value.trim() === "") {
        return fallback;
    }

    try {
        return JSON.parse(value);
    } catch (error) {
        throw new Error(
            `Environment variable ${name} is not valid JSON: ` +
            error.message
        );
    }
}

function normalizePrivateKey(privateKey) {
    return privateKey.replace(/\\n/g, "\n");
}

//////////////////////////////////////////////////////
// SECURITY HELPERS
//////////////////////////////////////////////////////

function secureStringEquals(actualValue, expectedValue) {
    const actual = Buffer.from(
        String(actualValue || ""),
        "utf8"
    );

    const expected = Buffer.from(
        String(expectedValue || ""),
        "utf8"
    );

    if (actual.length !== expected.length) {
        return false;
    }

    return crypto.timingSafeEqual(actual, expected);
}

//////////////////////////////////////////////////////
// IP ADDRESS HANDLING
//////////////////////////////////////////////////////

function normalizeIp(ip) {
    if (!ip) {
        return "";
    }

    let value = String(ip).trim();

    /*
     * Fjern IPv4-mapped IPv6 prefix.
     *
     * Eksempel:
     * ::ffff:77.241.128.172
     */
    if (value.startsWith("::ffff:")) {
        value = value.substring(7);
    }

    /*
     * IPv6 med port kan være skrevet som:
     *
     * [2001:db8::1]:443
     */
    if (value.startsWith("[")) {
        const closingBracket = value.indexOf("]");

        if (closingBracket !== -1) {
            return value
                .substring(1, closingBracket)
                .toLowerCase();
        }
    }

    /*
     * Azure Static Web Apps sender IPv4 med port:
     *
     * 77.241.128.172:29197
     *
     * Vi skal kun bruge selve IP-adressen.
     */
    const ipv4WithOptionalPort =
        value.match(
            /^(\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?$/
        );

    if (ipv4WithOptionalPort) {
        return ipv4WithOptionalPort[1];
    }

    return value.toLowerCase();
}

function getClientIp(req) {
    const headers = req.headers || {};

    /*
     * Azure Static Web Apps sender typisk:
     *
     * x-forwarded-for:
     * klient-IP:port, Azure-proxy-IP:port
     *
     * Eksempel:
     * 77.241.128.172:29197, 13.69.116.11:63889
     *
     * Den første adresse er den oprindelige klient.
     */
    const xForwardedFor =
        headers["x-forwarded-for"] ||
        headers["X-Forwarded-For"];

    if (xForwardedFor) {
        const addresses = String(xForwardedFor)
            .split(",")
            .map(address => normalizeIp(address))
            .filter(Boolean);

        if (addresses.length > 0) {
            return addresses[0];
        }
    }

    /*
     * Fallback, hvis x-forwarded-for mod forventning
     * ikke findes.
     */
    const fallbackIp =
        headers["x-client-ip"] ||
        headers["X-Client-IP"] ||
        headers["x-azure-clientip"] ||
        headers["X-Azure-ClientIP"] ||
        headers["client-ip"] ||
        headers["Client-IP"];

    return normalizeIp(fallbackIp);
}

function isIpAllowed(clientIp, allowedIps) {
    if (
        !Array.isArray(allowedIps) ||
        allowedIps.length === 0
    ) {
        return false;
    }

    /*
     * Kun til eventuel midlertidig test.
     * Brug ikke "*" i produktion.
     */
    if (allowedIps.includes("*")) {
        return true;
    }

    const normalizedClientIp =
        normalizeIp(clientIp);

    return allowedIps.some(allowedIp => {
        return (
            normalizeIp(allowedIp) ===
            normalizedClientIp
        );
    });
}

//////////////////////////////////////////////////////
// REPORT ALLOWLIST
//////////////////////////////////////////////////////

function isReportAllowed(
    siteConfig,
    groupId,
    reportId
) {
    if (!siteConfig) {
        return false;
    }

    const allowedReports =
        siteConfig.allowedReports;

    /*
     * Nuværende praktiske model:
     *
     * En tom allowedReports-liste betyder, at rapporten
     * tillades efter device-, key-, site- og IP-check.
     *
     * Senere kan listen gøres strict ved at indsætte
     * reportId og groupId eksplicit.
     */
    if (
        !Array.isArray(allowedReports) ||
        allowedReports.length === 0
    ) {
        return true;
    }

    const normalizedGroupId =
        String(groupId || "").toLowerCase();

    const normalizedReportId =
        String(reportId || "").toLowerCase();

    return allowedReports.some(report => {
        return (
            String(report.groupId || "").toLowerCase() ===
                normalizedGroupId &&
            String(report.reportId || "").toLowerCase() ===
                normalizedReportId
        );
    });
}

//////////////////////////////////////////////////////
// DEVICE ACCESS VALIDATION
//////////////////////////////////////////////////////

function validateDeviceAccess(req, body) {
    const accessConfig = parseJsonEnv(
        "DEVICE_ACCESS_CONFIG",
        null
    );

    if (!accessConfig) {
        throw new Error(
            "Missing DEVICE_ACCESS_CONFIG environment variable."
        );
    }

    const site = String(body.site || "");
    const device = String(body.device || "");
    const key = String(body.key || "");
    const groupId = String(body.groupId || "");
    const reportId = String(body.reportId || "");

    if (!site || !device || !key) {
        return {
            ok: false,
            status: 403,
            error: "Missing site, device or key."
        };
    }

    const devices =
        accessConfig.devices || {};

    const deviceConfig =
        devices[device];

    if (!deviceConfig) {
        return {
            ok: false,
            status: 403,
            error: "Unknown device."
        };
    }

    if (
        !secureStringEquals(
            key,
            deviceConfig.key
        )
    ) {
        return {
            ok: false,
            status: 403,
            error: "Invalid device key."
        };
    }

    if (
        String(deviceConfig.site || "") !==
        site
    ) {
        return {
            ok: false,
            status: 403,
            error:
                "Device is not allowed for this site."
        };
    }

    const clientIp = getClientIp(req);

    if (
        !isIpAllowed(
            clientIp,
            deviceConfig.allowedIps
        )
    ) {
        return {
            ok: false,
            status: 403,
            error:
                "IP is not allowed for this device. " +
                `Detected IP: ${clientIp || "unknown"}.`
        };
    }

    const sites =
        accessConfig.sites || {};

    const siteConfig =
        sites[site];

    if (
        !isReportAllowed(
            siteConfig,
            groupId,
            reportId
        )
    ) {
        return {
            ok: false,
            status: 403,
            error:
                "Report is not allowed for this site."
        };
    }

    return {
        ok: true,
        site,
        device,
        clientIp
    };
}

//////////////////////////////////////////////////////
// MICROSOFT / POWER BI AUTHENTICATION
//////////////////////////////////////////////////////

async function getPowerBiAccessToken() {
    const tenantId =
        getRequiredEnv("TENANT_ID");

    const clientId =
        getRequiredEnv("CLIENT_ID");

    const certThumbprint =
        getRequiredEnv("CERT_THUMBPRINT");

    const certPrivateKey =
        normalizePrivateKey(
            getRequiredEnv("CERT_PRIVATE_KEY")
        );

    const powerBiScope =
        process.env.POWERBI_SCOPE ||
        "https://analysis.windows.net/powerbi/api/.default";

    const msalConfig = {
        auth: {
            clientId,
            authority:
                `https://login.microsoftonline.com/${tenantId}`,

            clientCertificate: {
                thumbprint: certThumbprint,
                privateKey: certPrivateKey
            }
        }
    };

    const confidentialClient =
        new msal.ConfidentialClientApplication(
            msalConfig
        );

    const result =
        await confidentialClient
            .acquireTokenByClientCredential({
                scopes: [powerBiScope]
            });

    if (
        !result ||
        !result.accessToken
    ) {
        throw new Error(
            "Could not acquire Power BI access token."
        );
    }

    return result.accessToken;
}

//////////////////////////////////////////////////////
// POWER BI API
//////////////////////////////////////////////////////

async function powerBiFetch(
    label,
    url,
    accessToken,
    options = {}
) {
    const response = await fetch(url, {
        ...options,

        headers: {
            Authorization:
                `Bearer ${accessToken}`,

            "Content-Type":
                "application/json",

            ...(options.headers || {})
        }
    });

    const text =
        await response.text();

    let body;

    try {
        body = text
            ? JSON.parse(text)
            : null;
    } catch {
        body = text;
    }

    if (!response.ok) {
        throw new Error(
            `${label} failed. ` +
            `Power BI API error ` +
            `${response.status} ` +
            `${response.statusText}: ` +
            `${JSON.stringify(body)}`
        );
    }

    return body;
}

//////////////////////////////////////////////////////
// RESPONSE HELPERS
//////////////////////////////////////////////////////

function createJsonResponse(
    status,
    body
) {
    return {
        status,

        headers: {
            "Content-Type":
                "application/json",

            "Access-Control-Allow-Origin":
                "*",

            "Cache-Control":
                "no-store"
        },

        body
    };
}

//////////////////////////////////////////////////////
// AZURE FUNCTION
//////////////////////////////////////////////////////

module.exports = async function (
    context,
    req
) {
    try {
        if (req.method === "OPTIONS") {
            context.res = {
                status: 204,

                headers: {
                    "Access-Control-Allow-Origin":
                        "*",

                    "Access-Control-Allow-Methods":
                        "POST, OPTIONS",

                    "Access-Control-Allow-Headers":
                        "Content-Type",

                    "Cache-Control":
                        "no-store"
                }
            };

            return;
        }

        const body =
            req.body || {};

        const name =
            body.name;

        const reportId =
            body.reportId;

        const groupId =
            body.groupId;

        const pageName =
            body.pageName;

        if (!reportId || !groupId) {
            context.res = createJsonResponse(
                400,
                {
                    error:
                        "Missing reportId or groupId."
                }
            );

            return;
        }

        //////////////////////////////////////////////////////
        // DEVICE / SITE / IP VALIDATION
        //////////////////////////////////////////////////////

        const access =
            validateDeviceAccess(
                req,
                body
            );

        if (!access.ok) {
            context.log.warn(
                "Access denied. " +
                `Site=${body.site || "unknown"}, ` +
                `Device=${body.device || "unknown"}, ` +
                `IP=${getClientIp(req) || "unknown"}, ` +
                `Reason=${access.error}`
            );

            context.res =
                createJsonResponse(
                    access.status || 403,
                    {
                        error: access.error
                    }
                );

            return;
        }

        context.log(
            "Access granted. " +
            `Site=${access.site}, ` +
            `Device=${access.device}, ` +
            `IP=${access.clientIp}, ` +
            `Report=${reportId}`
        );

        //////////////////////////////////////////////////////
        // GET POWER BI ACCESS TOKEN
        //////////////////////////////////////////////////////

        const accessToken =
            await getPowerBiAccessToken();

        //////////////////////////////////////////////////////
        // GET REPORT DETAILS
        //////////////////////////////////////////////////////

        const reportUrl =
            "https://api.powerbi.com/v1.0/myorg/" +
            `groups/${encodeURIComponent(groupId)}/` +
            `reports/${encodeURIComponent(reportId)}`;

        const report =
            await powerBiFetch(
                "Get report",
                reportUrl,
                accessToken
            );

        //////////////////////////////////////////////////////
        // GENERATE EMBED TOKEN
        //////////////////////////////////////////////////////

        const generateTokenUrl =
            "https://api.powerbi.com/v1.0/myorg/" +
            `groups/${encodeURIComponent(groupId)}/` +
            `reports/${encodeURIComponent(reportId)}/` +
            "GenerateToken";

        const tokenResponse =
            await powerBiFetch(
                "Generate embed token",
                generateTokenUrl,
                accessToken,
                {
                    method: "POST",

                    body: JSON.stringify({
                        accessLevel: "View"
                    })
                }
            );

        //////////////////////////////////////////////////////
        // SUCCESS RESPONSE
        //////////////////////////////////////////////////////

        context.res =
            createJsonResponse(
                200,
                {
                    name,
                    reportId,
                    groupId,
                    pageName,

                    embedUrl:
                        report.embedUrl,

                    accessToken:
                        tokenResponse.token,

                    tokenExpiration:
                        tokenResponse.expiration,

                    tokenType:
                        "Embed",

                    mode:
                        "powerbi-embedded"
                }
            );
    } catch (error) {
        context.log.error(
            "getEmbedConfig failed:",
            error
        );

        context.res =
            createJsonResponse(
                500,
                {
                    error:
                        error.message ||
                        "Unexpected server error."
                }
            );
    }
};
