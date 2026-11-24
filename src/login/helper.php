<?php
declare(strict_types=1);

/**
 * WiseAdmin Login Security 全局辅助函数
 *
 * 通过 composer autoload.files 自动加载
 * 业务层可使用这些短函数快速调用登录安全相关能力
 */

if (!function_exists('wise_login_security_captcha')) {
    /**
     * 快速生成验证码
     *
     * 用法：$data = auth_login_captcha();
     *       return json(['key' => $data['key'], 'image' => $data['image']]);
     */
    function auth_login_captcha(): array
    {
        return \wise\login\facade\Captcha::generate();
    }
}

if (!function_exists('wise_login_security_captcha_check')) {
    /**
     * 快速校验验证码
     */
    function auth_login_captcha_check(string $key, string $input): bool
    {
        return \wise\login\facade\Captcha::verify($key, $input);
    }
}

if (!function_exists('wise_login_security_event')) {
    /**
     * 快速记录安全事件
     */
    function auth_login_event(string $type, array $data = [], ?\think\Request $request = null, ?string $username = null): void
    {
        \wise\login\facade\Logger::log($type, $data, $request, $username);
    }
}

if (!function_exists('wise_login_security_route')) {
    /**
     * 获取包内注册的验证码路由 URL
     *
     * 用法：
     *   auth_login_route('create')  → /wise/captcha/create
     *   auth_login_route('verify')  → /wise/captcha/verify
     *   auth_login_route('image')   → /wise/captcha/image
     *
     * 路由前缀可通过 config('wise-auth.login.route.prefix') 修改。
     *
     * @param  string $name   路由名：create | verify | image
     * @param  array  $params 可选查询参数（?foo=bar）
     * @return string
     */
    function auth_login_route(string $name, array $params = []): string
    {
        $prefix = \think\facade\Config::get('wise-auth.login.route.prefix', 'wise/captcha');

        $paths = [
            'create' => '/create',
            'verify' => '/verify',
            'image'  => '/image',
        ];

        if (!isset($paths[$name])) {
            return (string) url('/' . trim($prefix, '/'));
        }

        $path = $paths[$name];
        $url = '/' . trim($prefix, '/') . $path;

        if (!empty($params)) {
            $url .= '?' . http_build_query($params);
        }

        return (string) url($url);
    }
}
