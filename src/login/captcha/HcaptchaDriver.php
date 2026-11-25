<?php
declare(strict_types=1);

namespace wise\login\captcha;

use think\App;

/**
 * hCaptcha 验证码驱动＼�
 *
 * 对接 hCaptcha 国际验证码服务，适合面向海外用户的应用。
 * 无外部 SDK 依赖，直接调用 hCaptcha 验证 API。
 *
 * 配置：config('wise-auth.login.captcha.hcaptcha')
 *   - site_key: hCaptcha site key（前端使用）
 *   - secret_key: hCaptcha 密钥（仅用于服务端校验）
 *   - api_server: 默认 https://api.hcaptcha.com/siteverify
 *
 * 前端集成：
 *   1. <script src="https://js.hcaptcha.com/1/api.js" async defer></script>
 *   2. <div class="h-captcha" data-sitekey="xxx"></div>
 *   3. 表单提交时携带 h-captcha-response 字段
 *   4. 后端 verify(key, h-captcha-response) 校验
 */
class HcaptchaDriver implements CaptchaDriverInterface
{
    protected string $siteKey;
    protected string $secretKey;
    protected string $apiServer;

    public function __construct(protected App $app)
    {
        $cfg = (array) $this->app->config->get('wise-auth.login.captcha.hcaptcha', []);
        $this->siteKey = (string) ($cfg['site_key'] ?? '');
        $this->secretKey = (string) ($cfg['secret_key'] ?? '');
        $this->apiServer = (string) ($cfg['api_server'] ?? 'https://api.hcaptcha.com/siteverify');
    }

    public function getName(): string
    {
        return 'hcaptcha';
    }

    public function generate(): array
    {
        $expire = time() + (int) ($this->app->config->get('wise-auth.login.captcha.expire', 300));

        return [
            'image'  => '',
            'key'    => '',
            'mime'   => 'application/json',
            'expire' => $expire,
            'extra'  => [
                'driver'   => 'hcaptcha',
                'site_key' => $this->siteKey,
                'js_url'   => 'https://js.hcaptcha.com/1/api.js',
            ],
        ];
    }

    public function verify(string $key, string $input): bool
    {
        if ($input === '') {
            return false;
        }

        $userIp = $this->getRequestIp();

        $postData = http_build_query([
            'secret'   => $this->secretKey,
            'response' => $input,
            'remoteip' => $userIp,
        ]);

        try {
            $response = $this->httpPost($this->apiServer, $postData, 'application/x-www-form-urlencoded');
            $result = json_decode($response, true);
            if (!is_array($result)) {
                return false;
            }

            return (bool) ($result['success'] ?? false);
        } catch (\Throwable $e) {
            return false;
        }
    }

    protected function getRequestIp(): string
    {
        try {
            return $this->app->request->ip() ?: '127.0.0.1';
        } catch (\Throwable $e) {
            return '127.0.0.1';
        }
    }

    protected function httpPost(string $url, string $body, string $contentType = 'application/x-www-form-urlencoded'): string
    {
        if (function_exists('curl_init')) {
            $ch = curl_init($url);
            curl_setopt_array($ch, [
                CURLOPT_POST           => true,
                CURLOPT_POSTFIELDS     => $body,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT        => 5,
                CURLOPT_HTTPHEADER     => [
                    'Content-Type: ' . $contentType,
                ],
            ]);
            $result = curl_exec($ch);
            if ($result === false) {
                $error = curl_error($ch);
                curl_close($ch);
                throw new \RuntimeException("hCaptcha API request failed: {$error}");
            }
            curl_close($ch);
            return $result;
        }

        $opts = [
            'http' => [
                'method'  => 'POST',
                'header'  => "Content-Type: {$contentType}\r\n",
                'content' => $body,
                'timeout' => 5,
            ],
        ];
        $ctx = stream_context_create($opts);
        $result = @file_get_contents($url, false, $ctx);
        if ($result === false) {
            throw new \RuntimeException('hCaptcha API request failed');
        }
        return $result;
    }
}
