// Always
'use strict';

// Start Azure Application Insights as early as possible
let appInsights = require("applicationinsights");
appInsights.setup()
    .setSendLiveMetrics(true)
    .start();

let https = require("https");
https.globalAgent.keepAlive = true;

module.exports = async function (context, req) {
    context.log('JavaScript HTTP trigger function processed a request.');

    if (req.body && req.body.password) {
        let passwordToCheck = req.body.password;

        context.log.verbose("Password to check:", passwordToCheck);

        context.res = {
            // status: 200, /* Defaults to 200 */
            body: "Hello " + passwordToCheck
        };
    } else {
        context.res = {
            // B2C ValidationProfile requires specific result codes
            status: 409,
            body: "Required parameters are missing."
        };
    }
};
