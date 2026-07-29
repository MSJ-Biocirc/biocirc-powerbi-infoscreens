module.exports = async function (context, req) {
    const headers = req.headers || {};

    context.res = {
        status: 200,
        headers: {
            "Content-Type": "application/json",
            "Cache-Control": "no-store"
        },
        body: {
            xForwardedFor:
                headers["x-forwarded-for"] || null,

            xClientIp:
                headers["x-client-ip"] || null,

            clientIp:
                headers["client-ip"] || null,

            xAzureClientIp:
                headers["x-azure-clientip"] || null,

            allHeaders: headers
        }
    };
};
