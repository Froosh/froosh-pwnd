// Always
'use strict';

// Have-I-Been-Pwned config details
const hibpBaseURL = 'https://api.pwnedpasswords.com/range/';
const hibpOptions = {
    headers: {
        'Add-Padding': true
    }
};

// Start Azure Application Insights before anything else
const appInsights = require('applicationinsights');
appInsights.setup()
    .setSendLiveMetrics(true)
    .start();

const https = require('https');
https.globalAgent.keepAlive = true;

const axios = require('axios');
axios.default.httpsAgent = https.globalAgent;

const crypto = require('crypto');

const httpTrigger = async function (context, req) {
    const functionResult = {
        status: 200,
        headers: {
            'Content-Type': 'application/json'
        },
        body: {
            version: '1.1.0',
            passwordOk: false,
            status: 200,
            userMessage: null,

            // Debug Mode Return Values
            code: null,
            developerMessage: null,
            moreInfo: null,
            requestId: context.invocationId
        }
    };

    if (req.body && req.body.password) {
        // Generate SHA1 hash of the password and split it into prefix/suffix
        const sha1 = crypto.createHash('sha1');
        sha1.update(req.body.password);
        const sha1Digest = sha1.digest('hex').toUpperCase();
        const sha1Prefix = sha1Digest.slice(0, 5);
        const sha1Suffix = sha1Digest.slice(5);

        const hibpURL = encodeURI(`${hibpBaseURL}${sha1Prefix}`);

        context.log.info('Checking URL:', hibpURL);

        hibpOptions.headers["User-Agent"] = req.headers['user-agent'];

        await axios.get(hibpURL, hibpOptions)
            .then(function (response) {
                const dataArray = response.data.split('\r\n');
                context.log.info(`Received ${dataArray.length} result lines.`);

                // Chop the received data lines into suffix and count values
                // Then select the entry which matches the password SHA1 suffix (if any)
                const filteredArray = dataArray.map(function (line) {
                    const parts = line.split(':');
                    return {
                        suffix: parts[0],
                        count: parts[1]
                    };
                }).filter(function (entry) {
                    return entry.suffix === sha1Suffix;
                });

                // If an entry is found use the result, otherwise 0
                const sha1DigestCount = filteredArray.length === 1 ? filteredArray[0].count : 0;
                context.log.info(`Password Found ${sha1DigestCount} times.`);

                // Update the response for success/fail
                if (sha1DigestCount === 0) {
                    functionResult.body.passwordOk = true;
                } else {
                    functionResult.status = 409;
                    functionResult.body.status = 409;
                    functionResult.body.userMessage = `Your password has been exposed ${sha1DigestCount} times, choose another.`;
                }
            })
            .catch(function (error) {
                if (error.response) {
                    // The request was made and the server responded with a status code
                    // that falls out of the range of 2xx
                    console.log(error.response);

                    functionResult.status = error.response.status;
                    functionResult.body.status = error.response.status;

                    functionResult.body.code = error.response.status;
                    functionResult.body.developerMessage = error.response.data;
                    functionResult.body.moreInfo = error.response.headers;
                } else if (error.request) {
                    // The request was made but no response was received
                    // `error.request` is an instance of XMLHttpRequest in the browser and an instance of
                    // http.ClientRequest in node.js
                    console.log(error.request);

                    functionResult.body.developerMessage = error.request;
                } else {
                    // Something happened in setting up the request that triggered an Error
                    console.log('Error', error.message);

                    functionResult.body.developerMessage = error.message;
                }

                functionResult.body.userMessage = 'Error checking password against haveibeenpwned.';
            });
    } else {
        functionResult.body.userMessage = 'No password provided.';
    }

    context.log.verbose('Returning Result:', functionResult);
    context.res = functionResult;
};

// As per https://github.com/microsoft/ApplicationInsights-node.js#azure-functions
// To link request and dependency calls correctly
module.exports = async function (context, req) {
    // Start an AppInsights Correlation Context using the provided Function context
    const correlationContext = appInsights.startOperation(context, req);

    // Wrap the Function runtime with correlationContext
    return appInsights.wrapWithCorrelationContext(async () => {
        const startTime = Date.now(); // Start trackRequest timer

        // Run the Function
        await httpTrigger(context, req);

        // Track Request on completion
        appInsights.defaultClient.trackRequest({
            name: `${context.req.method} ${context.req.url}`,
            resultCode: context.res.status,
            success: true,
            url: req.url,
            duration: Date.now() - startTime,
            id: correlationContext.operation.parentId,
        });
        appInsights.defaultClient.flush();
    }, correlationContext)();
};
