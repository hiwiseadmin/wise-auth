<?php
declare(strict_types=1);

namespace wise\login\captcha;

use think\App;

/**
 * 腾讯云验证码驱动＼�
 *
 * 对接腾讯云验证码 2.0 / 3.0 服务端校验。
 *
 * 配置：config('wise-auth.login.captcha.tencent')
 *   - app_id: 腾讯云验证码 AppID
 *   - secret_key: 腾讯云验证码 AppSecretKey
 *   - api_server: 默认 https://ssl.captcha.qq.com/ticket/verify
 *
 * 前端集成：
 *   1. 加载 TencentCaptcha SDK
 *   2. new TencentCaptcha(appId, callback)
 *   3. callback 中获取 { ticket, randstr }
 *   4. 后端 verify(ticket, randstr) 校验
 */
class TencentCaptchaDriver implements CaptchaDriverInterface
{
    protected string $appId;
    protected string $secretKey;
    protected string $apiServer;

    public function __construct(protected App $app)
    {
        $cfg = (array) $this->app->config->get('wise-auth.login.captcha.tencent', []);
        $this->appId = (string) ($cfg['app_id'] ?? '');
        $this->secretKey = (string) ($cfg['secret_key'] ?? '');
        $this->apiServer = (string) ($cfg['api_server'] ?? 'https://ssl.captcha.qq.com/ticket/verify');
    }

    public function getName(): string
    {
        return 'tencent';
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
                'driver'     => 'tencent',
                'app_id'     => $this->appId,
            ],
        ];
    }

    public function verify(string $key, string $input): bool
    {
        $ticket = '';
        $randstr = '';

        $decoded = json_decode($input, true);
        if (is_array($decoded)) {
            $ticket = (string) ($decoded['ticket'] ?? $decoded['Ticket'] ?? '');
            $randstr = (string) ($decoded['randstr'] ?? $decoded['Randstr'] ?? '');
        } else {
            $parts = explode('|', $input);
            $ticket = $parts[0] ?? '';
            $randstr = $parts[1] ?? '';
        }

        if ($ticket === '') {
            return false;
        }

        $userIp = $this->getRequestIp();

        $params = http_build_query([
            'aid'          => $this->appId,
            'AppSecretKey' => $this->secretKey,
            'Ticket'       => $ticket,
            'Randstr'      => $randstr,
            'UserIP'       => $userIp,
        ]);

        try {
            $response = $this->httpGet($this->apiServer . '?' . $params);
            $result = json_decode($response, true);
            if (!is_array($result)) {
                return false;
            }

            $responseCode = (int) ($result['response'] ?? 0);
            $evilLevel = (int) ($result['evil_level'] ?? 100);

            $maxEvilLevel = (int) ($this->app->config->get(
                'wise-auth.login.captcha.tencent.max_evil_level',
                80
            ));

            return $responseCode === 1 && $evilLevel <= $maxEvilLevel;
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

    protected function httpGet(string $url): string
    {
        if (function_exists('curl_init')) {
            $ch = curl_init($url);
            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_CONNECTTIMEOUT => 3,
                CURLOPT_TIMEOUT        => 5,
            ]);
            $result = curl_exec($ch);
            if ($result === false) {
                $error = curl_error($ch);
                curl_close($ch);
                throw new \RuntimeException("Tencent CAPTCHA API request failed: {$error}");
            }
            curl_close($ch);
            return $result;
        }

        $context = stream_context_create([
            'http' => ['timeout' => 5, 'ignore_errors' => true],
        ]);

        $result = @file_get_contents($url, false, $context);
        if ($result === false) {
            throw new \RuntimeException('Tencent CAPTCHA API request failed');
        }
        return $result;
    }
}
