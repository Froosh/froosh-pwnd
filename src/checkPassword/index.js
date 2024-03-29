// Always
'use strict'

import applicationinsights from 'applicationinsights'

import axios from 'axios'

import { createHash } from 'node:crypto'

import https from 'node:https'

import { DefaultAzureCredential } from '@azure/identity'

// Start Azure Application Insights before anything else
applicationinsights.setup()
applicationinsights.start()

// Set up default managed service identity
const credential = new DefaultAzureCredential()

// Activate using credential to communicate with application insights
applicationinsights.defaultClient.config.aadTokenCredential = credential

// Have-I-Been-Pwned config details
const hibpBaseURL = 'https://api.pwnedpasswords.com/range/'
const hibpOptions = {
  decompress: true,
  headers: {
    // 'Accept-Encoding': 'gzip, compress, deflate',
    'Add-Padding': true
  },
  httpsAgent: new https.Agent({ keepAlive: true }),
  timeout: 500
}

const httpTrigger = async function (context, req) {
  const functionResult = {
    status: 200,
    headers: {
      'Content-Type': 'application/json; charset=utf-8'
    },
    body: {
      version: '0.3.0',
      passwordOk: false,
      status: 200,
      userMessage: null,

      // Debug Mode Return Values
      code: null,
      developerMessage: null,
      moreInfo: null,
      requestId: context.invocationId
    }
  }

  if (req.body && req.body.password) {
    // Generate SHA1 hash of the password and split it into prefix/suffix
    const sha1 = createHash('sha1')
    sha1.update(req.body.password)
    const sha1Digest = sha1.digest('hex').toUpperCase()
    const sha1Prefix = sha1Digest.slice(0, 5)
    const sha1Suffix = sha1Digest.slice(5)

    const hibpURL = encodeURI(`${hibpBaseURL}${sha1Prefix}`)

    context.log.info('Checking URL:', hibpURL)

    hibpOptions.headers['User-Agent'] = req.headers['user-agent']

    try {
      await axios
        .get(hibpURL, hibpOptions)
        .then(function (response) {
          const dataArray = response.data.split('\r\n')
          context.log.info(`Received ${dataArray.length} result lines.`)

          // Chop the received data lines into suffix and count values
          // Then select the entry which matches the password SHA1 suffix (if any)
          const filteredArray = dataArray
            .map(function (line) {
              const parts = line.split(':')
              return {
                suffix: parts[0],
                count: parts[1]
              }
            })
            .filter(function (entry) {
              return entry.suffix === sha1Suffix
            })

          // If an entry is found use the result, otherwise 0
          const sha1DigestCount =
            filteredArray.length === 1 ? filteredArray[0].count : 0
          context.log.info(`Password found ${sha1DigestCount} times.`)

          // Update the response for success/fail
          if (sha1DigestCount === 0) {
            functionResult.body.passwordOk = true
          } else {
            functionResult.status = 409
            functionResult.body.status = 409

            functionResult.body.userMessage = `Your password has been exposed ${sha1DigestCount} times, choose another.`
          }
        })
        .catch(function (error) {
          functionResult.status = 409
          functionResult.body.status = 409

          functionResult.body.userMessage =
            'Error checking password against haveibeenpwned.'

          if (error.response) {
            // The request was made and the server responded with a status code
            // that falls out of the range of 2xx
            context.log.error(error.response)

            functionResult.status = error.response.status
            functionResult.body.status = error.response.status

            functionResult.body.code = error.response.status
            functionResult.body.developerMessage = error.response.data
            functionResult.body.moreInfo = error.response.headers
          } else {
            // Something happened in setting up the request that triggered an Error
            context.log.error(error.message)
            functionResult.body.developerMessage = error.message
          }
        })
    } catch (error) {
      functionResult.status = 409
      functionResult.body.status = 409

      functionResult.body.userMessage =
        'Error checking password against haveibeenpwned.'

      context.log.error(JSON.stringify(error))
      functionResult.body.developerMessage = JSON.stringify(error)
    }
  } else {
    functionResult.body.userMessage = 'No password provided.'
  }

  context.log.verbose('Returning Result:', functionResult)
  context.res = functionResult
}

export default httpTrigger
