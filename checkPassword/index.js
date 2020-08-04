// Always
'use strict';

// Have-I-Been-Pwned config details
const hibpBaseURL = 'https://api.pwnedpasswords.com/range/';
const hibpOptions = {
    headers: { 'Add-Padding': true }
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

module.exports = async function (context, req) {
    context.log('JavaScript HTTP trigger function processed a request.');

    if (req.body && req.body.password) {
        let passwordToCheck = req.body.password;
        let sha1 = crypto.createHash('sha1');

        sha1.update(passwordToCheck);
        let sha1Digest = sha1.digest('hex').toUpperCase();
        let sha1Prefix = sha1Digest.slice(0, 5);
        let sha1Suffix = sha1Digest.slice(5);

        let hibpURL = `${hibpBaseURL}${encodeURIComponent(sha1Prefix)}`;

        context.log.verbose('Checking URL:', hibpURL);

        context.res = await axios.get(hibpURL, hibpOptions)
            .then(function (response) {
                context.log.verbose('Response Headers:', JSON.stringify(response.headers));

                let dataArray = response.data.split('\n');
                context.log.verbose(`Received ${dataArray.length} result lines`);

                let mappedArray = dataArray.map(function (line) {
                    let parts = line.split(':');
                    return {
                        suffix: parts[0].trim(),
                        count: parts[1].trim()
                    };
                });

                let filteredArray = mappedArray.filter(function (entry) {
                    return entry.suffix === sha1Suffix;
                });

                let sha1DigestCount = filteredArray[0] ? filteredArray[0].count : 0;

                return sha1DigestCount === 0 ? {
                    status: 200,
                    body: {
                        passwordOk: true
                    }
                } : {
                        status: 409,
                        body: {
                            version: '1.0.0',
                            status: 409,
                            userMessage: `This password has been exposed ${sha1DigestCount} times, choose another.`
                        }
                    };
            })
            .catch(function (error) {
                context.log.error(JSON.stringify(error));
                return {
                    status: 200,
                    body: {
                        passwordOk: false
                    }
                }
            });
    } else {
        context.res = {
            status: 200,
            body: {
                passwordOk: false
            }
        };
    }
};
