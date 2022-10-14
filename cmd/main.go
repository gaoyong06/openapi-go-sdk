package main

import (
	"fmt"
	"openapi-go-sdk/pkg/components/sign"
)

func main(){

	params := map[string]interface{}{
		"action" : "GetAvmUsageBandwidth",
		"accessKeyId" : "brT7SyYOggMvmzk1euPY",
		"timestamp" : "2022-10-08T04:12:00Z",
		"signatureNonce" : "65cab21e-2303-429f-9d12-3be4f06ccd40",
		"signatureMethod" : "HMAC-SHA1",
		"signatureVersion" : "1.0",
		"version" : "1.0",
		"avmId" : "AVMHW3CMT0A",
		"tesecode" : "+/= 123.~-_: $&+,/;?@",
	}

	signature := sign.GenSignV2("POST", "http","apiopen-cloudgame.xycloud.com", params, "wM0DT6UHxTzeiCA82usZOGSIflshhq");
	fmt.Println("step 7: sign is: " + signature)
}