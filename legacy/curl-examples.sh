#!/usr/bin/env bash
# What a legacy backend does — plain HTTP, no crypto libraries needed on its side.
H=${GATEWAY:-http://localhost:3000}
curl -s "$H/api/kyc/challenge?minAge=18"                       # 1. get nonce/sessionId, hand it to the customer's wallet
# 2. customer's wallet POSTs the proof bundle to $H/api/kyc/verify (or your backend forwards it)
# XML for SOAP-era systems:   curl -s -H 'Accept: application/xml' -d @bundle.json $H/api/kyc/verify
# Cross-check against the legacy DB record:  add  "expect": {"name":"Ahmed","university":"Osaka Metropolitan University"}  to the body
