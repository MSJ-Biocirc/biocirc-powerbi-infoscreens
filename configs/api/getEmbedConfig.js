module.exports = async function (context, req) {
    try {
        const body = req.body || {};

        const reportId = body.reportId;
        const groupId = body.groupId;
        const pageName = body.pageName;
        const name = body.name;

        if (!reportId || !groupId) {
            context.res = {
                status: 400,
                body: {
                    error: "Missing reportId or groupId"
                }
            };
            return;
        }

        context.res = {
            status: 200,
            body: {
                name: name,
                reportId: reportId,
                groupId: groupId,
                pageName: pageName,
                mode: "dummy",
                message: "Backend endpoint is reachable, but Power BI token generation is not implemented yet."
            }
        };
    }
    catch (error) {
        context.res = {
            status: 500,
            body: {
                error: error.message
            }
        };
    }
};
