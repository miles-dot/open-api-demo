package com.gookesoft;

import cn.hutool.core.util.RandomUtil;
import cn.hutool.crypto.Mode;
import cn.hutool.crypto.Padding;
import cn.hutool.crypto.SecureUtil;
import cn.hutool.crypto.asymmetric.AsymmetricAlgorithm;
import cn.hutool.crypto.asymmetric.KeyType;
import cn.hutool.crypto.asymmetric.RSA;
import cn.hutool.crypto.symmetric.AES;
import com.google.gson.Gson;
import okhttp3.*;

import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * 开放平台样例
 *
 * @author Miles
 */
public class DemoMain {

    public static void main(String[] args) throws Exception {

        String url = "https://xxx.com";

        String uri = "/xxxx/v1/task/list";

        Map<String, Object> map = new HashMap<String, Object>(2) {{
            put("taskId", "2020111214381881716");
            put("pageNo", "1");
        }};

        Gson gson = new Gson();

        String json = gson.toJson(map);

        System.out.println(json);

        String appId = "用户唯一ID";
        String appKey = "用户唯一密钥";
        String publicKey = "用户RSA加密公钥";

        String str = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

        String nonce = RandomUtil.randomString(str, 32);
        String time = String.valueOf(System.currentTimeMillis());

        TreeMap<String, String> treeMap = new TreeMap<>();

        treeMap.put("appId", appId);
        treeMap.put("nonce", nonce);
        treeMap.put("method", "POST");
        treeMap.put("timestamp", time);
        treeMap.put("body", json);
        treeMap.put("uri", uri);

        StringBuilder builder = new StringBuilder(appId);
        for (Map.Entry<String, String> entry : treeMap.entrySet()) {
            if (entry.getValue() == null || "".equals(entry.getValue())) {
                continue;
            }
            builder
                .append(entry.getKey())
                .append("=")
                .append(entry.getValue())
                .append("&");
        }
        String res = builder.substring(0, builder.length() - 1);
        char[] chars = res.toCharArray();
        Arrays.sort(chars);
        String s = SecureUtil.hmacSha256(appKey).digestHex(getBytes(chars));
        map.put("SIGNATURE_STR", s);

        json = gson.toJson(map);

        String aesKey = RandomUtil.randomString(str, 32);

        byte[] key = aesKey.getBytes(StandardCharsets.UTF_8);
        byte[] keyBytes = appKey.substring(8, 24).getBytes(StandardCharsets.UTF_8);

        AES aes = new AES(Mode.CBC, Padding.PKCS5Padding, key, keyBytes);

        json = aes.encryptBase64(json);

        byte[] bytes = Base64.getDecoder().decode(publicKey);
        RSA rsa = new RSA(AsymmetricAlgorithm.RSA_ECB_PKCS1.getValue());
        rsa.setPublicKey(SecureUtil.generatePublicKey(AsymmetricAlgorithm.RSA_ECB_PKCS1.getValue(), bytes));

        String enc = rsa.encryptBase64(aesKey, KeyType.PublicKey);

        String reqId = RandomUtil.randomString(str, 32);

        Map<String, String> param = new HashMap<>();

        param.put("reqId", reqId);
        param.put("appId", appId);
        param.put("nonce", nonce);
        param.put("timestamp", time);
        param.put("aesKey", enc);
        param.put("body", json);

        OkHttpClient client = new OkHttpClient();
        RequestBody body = RequestBody.create(gson.toJson(param), MediaType.get("application/json; charset=utf-8"));
        Request request = new Request.Builder()
            .url(url.concat(uri))
            .post(body)
            .build();
        try (Response response = client.newCall(request).execute()) {
            ResponseBody resp = response.body();
            if (!Objects.isNull(resp)) {
                System.out.println(resp.string());
            }
        }
    }

    /**
     * Chars 转 bytes
     * @param chars
     * @return
     */
    public static byte[] getBytes(char[] chars) {
        return StandardCharsets.UTF_8.encode(CharBuffer.wrap(chars)).array();
    }
}
