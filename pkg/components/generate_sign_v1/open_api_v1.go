/*
 * @Author: gaoyong
 * @Date: 2022-08-02 16:04:34
 * @LastEditors: gaoyong gaoyong06@qq.com
 * @LastEditTime: 2022-08-03 17:42:54
 * @FilePath: /halo/open_api/open_api_v1.go
 * @Description: OpenApi签名算法工具
 */

package generate_sign_v1

import (
	"bytes"
	"crypto/md5"
	"fmt"
	_ "net/http"
	"sort"
)

/**
 * @description: 生成 openapi v1版本签名
 * @param {map[string]string} params 请求参数
 * @param {string} secret appid 对应密钥
 * @return {*}
 */
func GenSignature(params map[string]string, secret string) string {
	var keys []string
	for key, _ := range params {
		keys = append(keys, key)
	}

	sort.Strings(keys)
	buf := make([]byte, 0)
	buffer := bytes.NewBuffer(buf)
	for i := 0; i < len(keys); i++ {
		key := keys[i]
		buffer.WriteString(keys[i])
		buffer.WriteString("=")
		buffer.WriteString(params[key])
		if i != len(keys)-1 {
			buffer.WriteString("&")
		}
	}
	buffer.WriteString(secret)
	return fmt.Sprintf("%x", md5.Sum(buffer.Bytes()))
}
