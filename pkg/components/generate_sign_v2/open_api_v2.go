package generate_sign_v2

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

/**
 * @description: 生成 openapi v2版本签名
 * @param {string} method 请求方式 例如： "GET"
 * @param {string} protocol 请求协议 例如："http"
 * @param {string} domain 请求域名
 * @param {map[string]string} params 请求参数
 * @param {string} secret appid 对应密钥
 * @return {*}
 */
func GenSignature(method, protocol, domain string, params map[string]interface{}, secret string) string {
	// 参数排序
	sortParamKeys := getSortParamKeys(params)

	//获取待签名字符串
	stringToBeSignature := getStringToBeSignature(protocol, domain, method, sortParamKeys, params)

	// 获取accessKeyId 对应密钥进行加密并将加密结果进行urlEncode
	unencodedSignature := base64HmacSh1(stringToBeSignature, secret)
	signature := urlEncode(unencodedSignature)
	fmt.Printf("(GenSignature) [step 6] method: %s protocol: %s domain: %s params: %+v secret: %s,sortParamKeys: %+v, stringToBeSignature: %s, unencodedSignature: %s, signature: %s", method, protocol, domain, params, secret, sortParamKeys, stringToBeSignature, unencodedSignature, signature)
	return signature
}

// getSortParamKeys 参数排序
func getSortParamKeys(params map[string]interface{}) []string {
	var sortParamKeys []string
	for key, _ := range params {
		sortParamKeys = append(sortParamKeys, key)
	}
	//参数排序
	sort.Strings(sortParamKeys)
	fmt.Printf("(getSortParamKeys) step 1: params: %+v, sortParamKeys: %+v", params, sortParamKeys)
	return sortParamKeys
}

// GetEncodeParams 对排序后请求参数 key-value 进行编码
func getEncodeParams(sortParamKeys []string, params map[string]interface{}) []string {
	//对请求参数和参数值进行编码
	//字符A~Z、a~z、0~9以及字符-、_、.、~不编码
	//对其它ASCII码字符进行编码。编码格式为%加上16进制的 ASCII 码。例如半角双引号（"）将被编码为 %22
	//  - 非 ASCII 码通过 UTF-8 编码。
	//  - 空格编码成%20，而不是加号（+）
	var encodeParams []string
	for i, val := range sortParamKeys {
		paramVal := params[val]
		buf := make([]byte, 0)
		buffer := bytes.NewBuffer(buf)
		//对参数编码
		decode := pathEncode(val)
		//对参数值编码
		var valCode string
		if va, ok := paramVal.(string); ok {
			valCode = pathEncode(va)
		} else {
			paramByteVal, _ := json.Marshal(paramVal)
			valCode = pathEncode(string(paramByteVal))
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
		if i != len(sortParamKeys)-1 {
			buffer.WriteString("&")
		}
		queryUrl := buffer.String()
		encodeParams = append(encodeParams, queryUrl)
	}
	fmt.Printf("(getEncodeParams) [step 2] sortParamKeys: %+v, params: %+v, encodeParams: %+v", sortParamKeys, params, encodeParams)
	return encodeParams
}

// GetCanoniCalizedQueryString 获取v2版本规范化请求字符串
func getCanoniCalizedQueryString(protocol, domain string, encodeParams []string) string {
	//规范化请求字符串
	CanoniCalizedQueryString := protocol + "://" + domain + "/v2/index?"
	queryParam := ""
	for i := 0; i < len(encodeParams); i++ {
		queryParam = queryParam + encodeParams[i]
	}

	CanoniCalizedQueryString = CanoniCalizedQueryString + queryParam
	fmt.Printf("(getCanonicalizedQueryString) [step 3] protocol: %s, domain: %s, encodeParams: %+v, canonicalizedQueryString: %s", protocol, domain, encodeParams, CanoniCalizedQueryString)
	return CanoniCalizedQueryString
}

// getStringToBeSignature 获取待签名字符串
func getStringToBeSignature(protocol, domain, method string, sortParamKeys []string, params map[string]interface{}) string {

	//获取编码后的参数
	encodeParams := getEncodeParams(sortParamKeys, params)

	//拼接规范化请求字符串
	CanoniCalizedQueryString := getCanoniCalizedQueryString(protocol, domain, encodeParams)

	//构造签名字符串
	encodeStr := urlEncode("/")
	encodeCanoniCalizedQueryString := urlEncode(CanoniCalizedQueryString)
	stringToBeSignature := method + "&" + encodeStr + "&" + encodeCanoniCalizedQueryString

	fmt.Printf("(getStringToBeSignature) [step 4] method: %s, protocol: %s, domain: %s, sortParamKeys: %+v, params: %+v, canonicalizedQueryString: %s, encodeCanonicalizedQueryString: %s, stringToBeSignature: %s", method, protocol, domain, sortParamKeys, params, CanoniCalizedQueryString, encodeCanoniCalizedQueryString, stringToBeSignature)
	return stringToBeSignature
}

// base64HmacSh1 使用sh1加密后做base64编码
func base64HmacSh1(str string, key string) string {
	keys := []byte(key + "&")
	mac := hmac.New(sha1.New, keys)
	mac.Write([]byte(str))
	fmt.Printf("(base64HmacSh1) step 5: input 加密字符串:%s 加密secret:%s 加密二进制密钥secret+&:%b ", str, key, keys)
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// urlEncode url编码
func urlEncode(str string) string {
	// QueryEscape 会对 " " 编码为 "+" 且会对 ":" 进行编码 ，openapi 编码要求，" " 需要编码成 "%20" 而不是"+" 因此参数编码不能使用该编码方式，需要使用 PathEscape
	escapeUrl := url.QueryEscape(str)
	return escapeUrl
}

// pathEncode 参数编码
func pathEncode(str string) string {
	// PathEscape 会对 " " 编码为 "%20" 且不会对 ":" 进行编码 ,因为 openapi 编码要求，" " 需要编码成 "%20" 而不是"+" 所以采用该方式进行参数编码
	// 因此在得到 规范化字符串时，需要将":" 提前编码 将其替换为 "%3A"，后使用 QueryEscape 统一进行编码计算签名
	escapeUrl := url.PathEscape(str)
	return escapeUrl
}
