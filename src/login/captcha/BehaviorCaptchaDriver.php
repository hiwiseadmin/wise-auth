<?php
declare(strict_types=1);

namespace wise\login\captcha;

use think\App;

/**
 * 行为验证码驱动（极验 Geetest 等）占位
 *
 * 完整对接需要：
 *  1. composer require geetest/geetest
 *  2. 继承本类并实现 validate() 中的二次校验逻辑
 *  3. 在配置 captcha.driver 中将 'geetest' 指向你的子类
 *
 * 也可以直接实现 CaptchaDriverInterface 注册到容器。
 */
class BehaviorCaptchaDriver implements CaptchaDriverInterface
{
    public function __construct(protected App $app)
    {
    }

    public function getName(): string
    {
        return 'geetest';
    }

    /**
     * 生成行为验证码前端所需的 register 参数
     */
    public function generate(): array
    {
        $cfg = (array) $this->app->config->get('wise-auth.login.captcha.geetest', []);

        return [
            'image'  => '',
            'key'    => '',
            'mime'   => 'application/json',
            'expire' => time() + (int) ($this->app->config->get('wise-auth.login.captcha.expire', 300)),
            'extra'  => [
                'geetest_id'   => (string) ($cfg['id'] ?? ''),
                'api_server'   => (string) ($cfg['api_server'] ?? 'https://api.geetest.com'),
            ],
        ];
    }

    public function verify(string $key, string $input): bool
    {
        return false;
    }
}
