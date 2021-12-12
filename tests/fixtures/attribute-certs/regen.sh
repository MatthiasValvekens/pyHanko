#!/bin/sh


certomancer mass-summon basic-aa basic-aa --no-pem --no-pfx
certomancer necronomicon --no-pem --at-time '2019-12-01T00:00:00+0000' basic-aa role-aa basic-aa/role-aa-all-good.crl
certomancer necronomicon --no-pem --at-time '2021-12-12T00:00:00+0000' basic-aa role-aa basic-aa/role-aa-some-revoked.crl
certomancer seance --at-time '2019-12-12T00:00:00+0000' basic-aa alice-role-with-rev role-aa basic-aa/alice-all-good.ors
certomancer seance --at-time '2021-12-12T00:00:00+0000' basic-aa alice-role-with-rev role-aa basic-aa/alice-revoked.ors