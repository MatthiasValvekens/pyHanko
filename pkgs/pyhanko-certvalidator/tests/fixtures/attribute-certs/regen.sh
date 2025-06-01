#!/bin/sh


certomancer mass-summon basic-aa basic-aa --no-pem --no-pfx
certomancer necronomicon --no-pem --at-time '2019-12-01T00:00:00+0000' basic-aa interm basic-aa/interm/interm-all-good.crl
certomancer necronomicon --no-pem --at-time '2019-12-01T00:00:00+0000' basic-aa root basic-aa/root/root-all-good.crl
certomancer necronomicon --no-pem --at-time '2021-12-12T00:00:00+0000' basic-aa root basic-aa/root/root-some-revoked.crl
certomancer necronomicon --no-pem --at-time '2021-12-12T00:00:00+0000' basic-aa interm basic-aa/interm/interm-some-revoked.crl

certomancer necronomicon --no-pem --at-time '2019-12-01T00:00:00+0000' basic-aa role-aa basic-aa/role-aa-all-good.crl
certomancer necronomicon --no-pem --at-time '2021-12-12T00:00:00+0000' basic-aa role-aa basic-aa/role-aa-some-revoked.crl
certomancer seance --at-time '2019-12-12T00:00:00+0000' basic-aa alice-role-with-rev role-aa basic-aa/alice-all-good.ors
certomancer seance --at-time '2021-12-12T00:00:00+0000' basic-aa alice-role-with-rev role-aa basic-aa/alice-revoked.ors

certomancer necronomicon --no-pem --at-time '2019-12-01T00:00:00+0000' basic-aa role-aa-nonaligned-name basic-aa/role-aa-nonaligned-name.crl
certomancer necronomicon --no-pem --at-time '2019-12-01T00:00:00+0000' basic-aa role-aa-nonsensically-scoped basic-aa/role-aa-nonsensically-scoped.crl
certomancer necronomicon --no-pem --at-time '2019-12-01T00:00:00+0000' basic-aa role-aa-other-reasons basic-aa/role-aa-other-reasons-all-good.crl
certomancer necronomicon --no-pem --at-time '2019-12-01T00:00:00+0000' basic-aa role-aa-aa-compromise basic-aa/role-aa-aa-compromise-all-good.crl
certomancer necronomicon --no-pem --at-time '2019-12-01T00:00:00+0000' basic-aa role-aa-other-reasons basic-aa/role-aa-other-reasons-all-good.crl
certomancer necronomicon --no-pem --at-time '2021-12-12T00:00:00+0000' basic-aa role-aa-aa-compromise basic-aa/role-aa-aa-compromise-some-revoked.crl
certomancer necronomicon --no-pem --at-time '2021-12-12T00:00:00+0000' basic-aa role-aa-other-reasons basic-aa/role-aa-other-reasons-some-revoked.crl
