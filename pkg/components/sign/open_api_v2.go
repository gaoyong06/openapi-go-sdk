package sign

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// GenSignV2 openapi v2 鉴权获取计算签名
func GenSignV2(method, protocol, domain string, params map[string]interface{}, secret string) string {
	fmt.Printf("step 1 :GenSignV2 input method:%s protocol:%s domain:%s param:%+v secret:%s", method, protocol, domain, params, secret)
	// 参数排序
	keys := sortParamsV2(params)
	fmt.Printf("step 2 :GenSignV2 SortParams key is %+v", keys)

	//获取待签名字符串
	stringToSign := getStringToSignV2(protocol, domain, method, keys, params)

	//取 accessKeyId 对应密钥进行加密并将加密结果进行urlencode
	encodeSignature, unencodeSignature := base64HmacSh1(stringToSign, secret)
	fmt.Printf("step 7 :GenSignV2 HmacSh1 加密结果 encodeSignature is %s ,unencodeSignature is %s", encodeSignature, unencodeSignature)
	return encodeSignature
}

// SortParams 参数排序
func sortParamsV2(params map[string]interface{}) []string {
	var keys []string
	for key, _ := range params {
		keys = append(keys, key)
	}
	//参数排序
	sort.Strings(keys)
	return keys
}

// GetEncodeParamsV2 对排序后请求参数 key-value 进行编码
func getEncodeParamsV2(keys []string, params map[string]interface{}) []string {
	//对请求参数和参数值进行编码
	//字符A~Z、a~z、0~9以及字符-、_、.、~不编码
	//对其它ASCII码字符进行编码。编码格式为%加上16进制的 ASCII 码。例如半角双引号（"）将被编码为 %22
	//  - 非 ASCII 码通过 UTF-8 编码。
	//  - 空格编码成%20，而不是加号（+）
	fmt.Printf("step 3 :GenSignV2 GetStringToSign input key:%+v params:%+v", keys, params)
	var DecoderParam []string
	for i, val := range keys {
		paramVal := params[val]
		buf := make([]byte, 0)
		buffer := bytes.NewBuffer(buf)
		//对参数编码
		decode := encodePath(val)
		//对参数值编码
		var valCode string
		if va, ok := paramVal.(string); ok {
			valCode = encodePath(va)
		} else {
			paramByteVal, _ := json.Marshal(paramVal)
			valCode = encodePath(string(paramByteVal))
		}
		// 由于golang encodePath 针对 + = : $ & @ 不会编码，不符合 UTF-8字符集按照RFC3986 编码规则 因此需要将其进行转化
		valCode = strings.ReplaceAll(valCode, "+", "%2B")
		valCode = strings.ReplaceAll(valCode, "=", "%3D")
		valCode = strings.ReplaceAll(valCode, ":", "%3A")
		valCode = strings.ReplaceAll(valCode, "$", "%24")
		valCode = strings.ReplaceAll(valCode, "&", "%26")
		valCode = strings.ReplaceAll(valCode, "@", "%40")

		//拼接参数
		key := decode
		buffer.WriteString(key)
		buffer.WriteString("=")
		buffer.WriteString(valCode)
		if i != len(keys)-1 {
			buffer.WriteString("&")
		}
		queryUrl := buffer.String()
		DecoderParam = append(DecoderParam, queryUrl)
	}
	return DecoderParam
}

// GetCanoniCalizedQueryStringV2 获取v2版本规范化请求字符串
func getCanoniCalizedQueryStringV2(protocol, domain string, DecoderParam []string) string {
	//规范化请求字符串
	CanoniCalizedQueryString := protocol + "://" + domain + "/v2/index?"
	queryParam := ""
	for i := 0; i < len(DecoderParam); i++ {
		queryParam = queryParam + DecoderParam[i]
	}

	CanoniCalizedQueryString = CanoniCalizedQueryString + queryParam
	fmt.Printf("step 4 :GenSignV2 GetStringToSign 规范化请求字符串 CanoniCalizedQueryString: %s", CanoniCalizedQueryString)
	return CanoniCalizedQueryString
}

// getStringToSignV2 获取待签名字符串
func getStringToSignV2(protocol, domain, method string, keys []string, params map[string]interface{}) string {

	//获取编码后的参数
	DecoderParam := getEncodeParamsV2(keys, params)

	//拼接规范化请求字符串
	CanoniCalizedQueryString := getCanoniCalizedQueryStringV2(protocol, domain, DecoderParam)

	//构造签名字符串
	encodeStr := encodeURI("/")
	encodeCanoniCalizedQueryString := encodeURI(CanoniCalizedQueryString)
	stringToSign := method + "&" + encodeStr + "&" + encodeCanoniCalizedQueryString

	fmt.Printf("step 5 :GenSignV2 GetStringToSign 规范化请求字符串 CanoniCalizedQueryString url编码后 待签名字符串 :%s", stringToSign)
	return stringToSign
}

// base64HmacSh1 sh1加密 返回 urlencode 的编码 和未 urlencode 的编码
func base64HmacSh1(str string, key string) (string, string) {
	keys := []byte(key + "&")
	mac := hmac.New(sha1.New, keys)
	mac.Write([]byte(str))
	fmt.Printf("step 6 :GenSignV2 HmacSh1 input 加密字符串:%s 加密secret:%s 加密二进制密钥secret+&:%b ", str, key, keys)
	return url.QueryEscape(base64.StdEncoding.EncodeToString(mac.Sum(nil))), base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// url编码
func encodeURI(str string) string {
	// QueryEscape 会对 " " 编码为 "+" 且会对 ":" 进行编码 ，openapi 编码要求，" " 需要编码成 "%20" 而不是"+" 因此参数编码不能使用该编码方式，需要使用 PathEscape
	escapeUrl := url.QueryEscape(str)
	return escapeUrl
}

// 参数编码
func encodePath(str string) string {
	// PathEscape 会对 " " 编码为 "%20" 且不会对 ":" 进行编码 ,因为 openapi 编码要求，" " 需要编码成 "%20" 而不是"+" 所以采用该方式进行参数编码
	// 因此在得到 规范化字符串时，需要将":" 提前编码 将其替换为 "%3A"，后使用 QueryEscape 统一进行编码计算签名
	escapeUrl := url.PathEscape(str)
	return escapeUrl
}
