<?php
declare(strict_types=1);

namespace wise\login\captcha;

use think\App;

/**
 * 极验 v4 行为验证码驱动＼�
 *
 * 完整实现极验证 v4（无感/滑块）的服务端校验。
 * 前端使用 initGeetest4 SDK，用户完成验证后获取 lot_number 等参数，
 * 后端通过 verify() 调用极验二次校验接口。
 *
 * 依赖：无（使用 ThinkPHP Http 或 curl 直接请求）
 *
 * 配置：config('wise-auth.login.captcha.geetest')
 *   - id: 极验 captcha_id
 *   - key: 极验 captcha_key（服务端密钥，仅用于二次校验）
 *   - api_server: 验证接口地址，默认 https://gcaptcha4.geetest.com/validate
 *
 * 前端集成步骤：
 *   1. POST /wise/captcha/create → 获取 geetest_id
 *   2. 初始化 initGeetest4({ captchaId: geetest_id, ... })
 *   3. 用户完成验证，拿到 { lot_number, captcha_output, pass_token, gen_time }
 *   4. POST /wise/captcha/verify → 发送上述参数到后端
 */
class GeetestV4CaptchaDriver implements CaptchaDriverInterface
{
    protected string $id;
    protected string $key;
    protected string $apiServer;

    public function __construct(protected App $app)
    {
        $cfg = (array) $this->app->config->get('wise-auth.login.captcha.geetest', []);
        $this->id = (string) ($cfg['id'] ?? '');
        $this->key = (string) ($cfg['key'] ?? '');
        $this->apiServer = (string) ($cfg['api_server'] ?? 'https://gcaptcha4.geetest.com/validate');
    }

    public function getName(): string
    {
        return 'geetest';
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
                'driver'     => 'geetest',
                'geetest_id' => $this->id,
                'api_server' => $this->apiServer,
            ],
        ];
    }

    public function verify(string $key, string $input): bool
    {
        $params = json_decode($input, true);
        if (!is_array($params)) {
            return false;
        }

        $lotNumber = (string) ($params['lot_number'] ?? '');
        $captchaOutput = (string) ($params['captcha_output'] ?? '');
        $passToken = (string) ($params['pass_token'] ?? '');
        $genTime = (string) ($params['gen_time'] ?? '');

        if ($lotNumber === '') {
            return false;
        }

        $signToken = $this->buildSignToken($lotNumber);

        $postData = http_build_query([
            'lot_number'     => $lotNumber,
            'captcha_output' => $captchaOutput,
            'pass_token'     => $passToken,
            'gen_time'       => $genTime,
            'sign_token'     => $signToken,
        ]);

        try {
            $url = $this->apiServer . '?captcha_id=' . urlencode($this->id);
            $response = $this->httpPost($url, $postData, 'application/x-www-form-urlencoded');
            $result = json_decode($response, true);
            if (!is_array($result)) {
                return false;
            }

            $status = (string) ($result['result'] ?? '');
            return $status === 'success';
        } catch (\Throwable $e) {
            return false;
        }
    }

    /**
     * 构建极验 v4 sign_token
     * sign_token = HMAC-SHA256(key = captcha_key, message = lot_number)
     */
    protected function buildSignToken(string $lotNumber): string
    {
        return hash_hmac('sha256', $lotNumber, $this->key);
    }

    /**
     * HTTP POST 封装
     */
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
                    'Accept: application/json',
                ],
            ]);
            $result = curl_exec($ch);
            if ($result === false) {
                $error = curl_error($ch);
                curl_close($ch);
                throw new \RuntimeException("Geetest API request failed: {$error}");
            }
            curl_close($ch);
            return $result;
        }

        $opts = [
            'http' => [
                'method'  => 'POST',
                'header'  => "Content-Type: {$contentType}\r\nAccept: application/json\r\n",
                'content' => $body,
                'timeout' => 5,
            ],
        ];
        $ctx = stream_context_create($opts);
        $result = @file_get_contents($url, false, $ctx);
        if ($result === false) {
            throw new \RuntimeException('Geetest API request failed');
        }
        return $result;
    }
}
