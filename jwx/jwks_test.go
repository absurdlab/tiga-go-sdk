package jwx_test

import (
	"github.com/absurdlab/tiga-go-sdk/jwx"
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

func TestReadKeySet(t *testing.T) {
	reader := strings.NewReader(`{
  "keys": [
    {
      "use": "sig",
      "kty": "EC",
      "kid": "772c06ee-c745-4c20-b9ba-99c36937311c",
      "crv": "P-256",
      "alg": "ES256",
      "x": "EsH2MPOm5_FifOAZcVr2f-u8YOBec7j3NeDyw_LrZQ8",
      "y": "9YBU9FDc9Z23yvQNx7Mm9Ca2Hu9FAD--VjaZvTv-WyQ",
      "d": "slzLInxpfESdp1WnHiic53k92Exnt2DNkiHoB39Eq0Y"
    },
    {
      "use": "sig",
      "kty": "RSA",
      "kid": "b64e1881-07b9-4ff1-b040-1ae75c537785",
      "alg": "RS256",
      "n": "mhX8N9gOQD0ZjYJppK-KKJyHJR4jKt1Vcfrs9qeIxBKBSQQ9su3olr_B2fPiAvH6EmOKiEq2SGUKbwh_GSoAryiaxJKGZZCvzsYM6LAERHh8VMYDqaGHMHzIwIv4S_H6SJ38R84mZx-Z-nT3GMwOmau1LO8JCpoeUurj0GgsjN7-f7AdIzj7kxeQE4JjdRdc2iFRu5-75an2U-Hx68ovHitIwmnR5wWtWzU4t7u-cuk4xNUTgH_ScYbHFNzEut3zECCVT7KECVkGy4LIZGk9U5-feaiiax41gy4g5fi6kCKKJ9rfX4gzCLDtGBxWiB0XZs-_I54IqdNOeXlcPjmiWw",
      "e": "AQAB",
      "d": "diO1Jfv5sTcniGAdL6-HdmvNEqBwxkS9Zo7FcLgzHGIzzg_6Xl4anrqXnsxm1WtCGSdI6AagjBEsVsVk7Z5Ot_2h7GWLtgOhSCCBdUa_fuACM90-oai_RmXmZfrrfQ8intrCuytMNnT8UhOsAM8zwo7scm8zt3VDGsANu5Sj071VH0nz9wAJwR5If0Oob13C7D0-c6TyeZ8Of5zFHdFfywtr-dYpbOiBQBjA5cGH70XTtk9vvHeY5qsfNmOdQCLtVvcEDk4Y7o2zywgP5eRygCBQXdwJHxsJLH3_qTen9sjPZRUCIAtaz3Ntl9DMIZUkCsjnlAXfnN799YzddEBNwQ",
      "p": "zOTbmi86kZdd-zqnj1FChAV5RHCPBq_bN2qUQptUNQ8jpF659Dv5M3uylVYOUSisWUAO52dEkH2R1LpNvOhbf9Y3Zyd6BQZamjxTqliVe2Ha_7dg7UMSjmLlYkDIiJtRolUP9pcHsMM6ruBPIrmnnmFxQJxt0ROJA8DvkpDKH0U",
      "q": "wITdyanA3aXt8nCIyOAZ4Q23cdaaUN8mDGYWWjLg2yRKADsUznMo7zY7l5wxfnxXL_6K4SpvRy3Fjl33zOh6Jfr_04Z7i_LxNOFfe2RfMCvK-tI8GMsYsaTfpluK1aXSyimVmiK2QQD0-Wb3crl2TMyReGOpFhxj_uNcPvkNhR8",
      "dp": "ECNukKRrrpAHnQQvsoAqBxAPTy62dUZgs-q3Js_pQAyjOA0mBHC83is-E7klg4r6mEUNZ3ig0-iwFdteyCRdIKKU1pErcT3g4QkjZeV4ULGSeFXPUqDX01NC0gxcPzZMpcahbUDUID4gXynX0dphs33lV7t6gt9RCXSm6hpxcSk",
      "dq": "VYbxbRTQDOgZVLpv2iXM-XF5jMZVGhZ4tctopLuzr0do5L9al_kLN3J1eP438sRUi4resfeDJjEMchoG625gTZ07qAI3ws20INT68Tt_GkxqSZG6hx07JDhl72b9v7qCcbOVtbs0Ep7VNjNrPPltt-Ktwbksthj4x5TEN2m3eus",
      "qi": "rfN9IuzcMjQNBjvKhvFigXgW8qxeYAjQi_5NLhDcjTTn7JghbelDkwpmdpd2ZJiibfmWyCbDhwOu0T8jpIUnzV80WXODyHKjIaSdKAbuaDW4PEMFmw6lhkED0uHbC78_F_kY2Qay7DPq8JDDXWVNLREca6LPTHnV7s7W01FhlNk"
    }
  ]
}
  `)

	ks, err := jwx.ReadKeySet(reader)
	assert.NoError(t, err)

	k, ok := ks.KeyForSigning(jwx.ES256)
	assert.True(t, ok)
	assert.NotNil(t, k)
}
