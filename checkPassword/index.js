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

module.exports = async function (context, req) {
    context.log.verbose('Context Received:', context);

    if (req.body && req.body.password) {
        // Generate SHA1 hash of the password and split it into prefix/suffix
        let sha1 = crypto.createHash('sha1');
        sha1.update(req.body.password);
        let sha1Digest = sha1.digest('hex').toUpperCase();
        let sha1Prefix = sha1Digest.slice(0, 5);
        let sha1Suffix = sha1Digest.slice(5);

        let hibpURL = encodeURI(`${hibpBaseURL}${sha1Prefix}`);

        context.log.info('Checking URL:', hibpURL);

        hibpOptions.headers["User-Agent"] = req.headers['user-agent'];

        context.res = await axios.get(hibpURL, hibpOptions)
            .then(function (response) {
                let dataArray = response.data.split('\r\n');
                context.log.verbose(`Received ${dataArray.length} result lines.`);

                // Chop the received data lines into suffix and count values
                // Then select the entry which matches the password SHA1 suffix (if any)
                let filteredArray = dataArray.map(function (line) {
                    let parts = line.split(':');
                    return {
                        suffix: parts[0],
                        count: parts[1]
                    };
                }).filter(function (entry) {
                    return entry.suffix === sha1Suffix;
                });

                // If an entry is found use the result, otherwise 0
                let sha1DigestCount = filteredArray.length === 1 ? filteredArray[0].count : 0;

                // Construct the HTTPS responses for success/fail
                return sha1DigestCount === 0 ? {
                    status: 200,
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: {
                        passwordOk: true
                    }
                } : {
                        status: 409,
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: {
                            version: '1.0.0',
                            status: 409,
                            userMessage: `This password has been exposed ${sha1DigestCount} times, choose another.`
                        }
                    };
            })
            .catch(function (error) {
                context.log.error(error);
                return {
                    status: 200,
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: {
                        passwordOk: false,
                        message: 'Error checking password against haveibeenpwned.'
                    }
                }
            });
    } else {
        context.res = {
            status: 200,
            headers: {
                'Content-Type': 'application/json'
            },
            body: {
                passwordOk: false,
                message: 'No password provided.'
            }
        };
    }
};
